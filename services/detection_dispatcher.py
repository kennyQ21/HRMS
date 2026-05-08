"""
services/detection_dispatcher.py
-----------------------------------
Detection Dispatcher — the core intelligence router.

Determines WHICH engines run, in WHAT ORDER, with what configuration.
All engines are COLLABORATIVE DETECTORS, not a fallback chain.

Execution model:
  ┌────────────┐
  │ Regex      │  Always runs (fast, deterministic)
  ├────────────┤
  │ Otter      │  Runs on documents (key-value forms, tables)
  ├────────────┤
  │ GLiNER     │  Runs on text ≥50 words (semantic NER)
  ├────────────┤
  │ Presidio   │  Runs as supplementary NER (legacy, kept for compatibility)
  ├────────────┤
  │ LLM/Qwen   │  Runs on medical/contextual/inferred types
  └────────────┘
         ↓
  Entity Resolution Layer

Routing decisions:
  - Short structured values (DB columns): Regex only
  - Document text / OCR output: all engines
  - Medical documents: all engines, LLM mandatory
  - Financial sheets: Regex + Otter
"""

from __future__ import annotations

import concurrent.futures
import logging
from dataclasses import dataclass, field
from typing import Optional

from constants import LLM_PRIORITY_PII, PII_TYPES, SEMANTIC_ONLY_PII
from services.engines.base_engine import EngineResult, PIIMatch
from services.engines.gliner_engine import GLiNEREngine
from services.engines.llm_engine import LLMEngine
from services.engines.otter_engine import OtterEngine
from services.engines.regex_engine import RegexEngine
from services.entity_resolution import (
    ResolvedEntity,
    resolve,
    resolved_to_pii_counts,
    select_primary_from_resolved,
)
from services.text_normalizer import NormalisedText, normalise

logger = logging.getLogger(__name__)


@dataclass
class DispatchResult:
    """
    Full output of the detection pipeline.

    Backward-compatible: exposes .matches (list[PIIMatch]) and .counts
    so existing routers (scans.py, files.py) continue to work unchanged.
    """
    resolved:       list[ResolvedEntity] = field(default_factory=list)
    engine_results: list[EngineResult]   = field(default_factory=list)
    normalised_text: Optional[NormalisedText] = None

    # ── Backward-compat helpers ──────────────────────────────────────────────

    @property
    def matches(self) -> list[PIIMatch]:
        """Flatten resolved entities to PIIMatch for legacy code."""
        out: list[PIIMatch] = []
        for e in self.resolved:
            out.append(PIIMatch(
                pii_type=e.pii_type,
                value=e.value,
                source="|".join(e.sources),
                confidence=e.confidence,
                start=e.start,
                end=e.end,
                context=e.context,
                metadata=e.metadata,
            ))
        return out

    @property
    def counts(self) -> dict[str, int]:
        return resolved_to_pii_counts(self.resolved)

    def select_primary(self, allowed_types: Optional[set[str]] = None):
        return select_primary_from_resolved(self.resolved, allowed_types)


# ── Singleton engine instances (lazy-init handled inside each engine) ─────────

_regex_engine   = RegexEngine()
_otter_engine   = OtterEngine()
_gliner_engine  = GLiNEREngine()
_llm_engine     = LLMEngine()


class DetectionDispatcher:
    """
    Orchestrates the multi-engine hybrid detection pipeline.

    Instantiate once (e.g. module-level singleton).  Thread-safe for
    concurrent requests — engine state is process-global, call-local.
    """

    def dispatch(
        self,
        text: str,
        use_nlp:     bool = True,
        use_llm:     bool = True,
        use_otter:   bool = True,
        parallel:    bool = True,
        allowed_pii: Optional[set[str]] = None,
        doc_type:    str = "generic",
    ) -> DispatchResult:
        """
        Run the full detection pipeline on *text*.

        Args:
            text:        Raw document or field text.
            use_nlp:     Enable GLiNER + Presidio (default True).
                         Set False for short DB column values.
            use_llm:     Enable LLM engine (default True).
                         Auto-disabled for short text (<50 words).
            use_otter:   Enable Otter structural extractor.
            parallel:    Run NLP/LLM engines concurrently (default True).
            allowed_pii: Restrict detection to these type IDs.
                         None = detect all MASTER_PIIS.
            doc_type:    Hint for routing:
                         "medical" | "financial" | "hr" | "id" | "generic"
        """
        if not text or not text.strip():
            return DispatchResult()

        # ── 1. Normalise ──────────────────────────────────────────────────────
        norm = normalise(text)
        working_text = norm.normalised

        word_count = len(working_text.split())
        is_short   = word_count < 20

        # ── 2. Routing overrides ──────────────────────────────────────────────
        _use_nlp   = use_nlp   and not is_short
        _use_llm   = use_llm   and not is_short
        _use_otter = use_otter and not is_short

        # Medical documents: LLM is mandatory regardless of length
        if doc_type == "medical":
            _use_llm = True

        # Financial: Otter is prioritised (key-value forms)
        if doc_type == "financial":
            _use_otter = True

        # Structured ID scanning (DB columns): Regex only
        if is_short and not _use_nlp:
            _use_otter = False
            _use_llm   = False

        logger.info(
            "[DISPATCHER] doc_type=%s words=%d | regex=✓ nlp=%s llm=%s otter=%s parallel=%s",
            doc_type, word_count,
            "✓" if _use_nlp else "✗",
            "✓" if _use_llm else "✗",
            "✓" if _use_otter else "✗",
            "✓" if parallel else "✗",
        )

        # ── 3. Engine execution ───────────────────────────────────────────────
        engine_results: list[EngineResult] = []

        # Regex always runs synchronously (it's fast and has no I/O)
        regex_result = _regex_engine.run(
            working_text,
            use_nlp=_use_nlp,
        )
        engine_results.append(regex_result)

        if not _use_nlp and not _use_llm and not _use_otter:
            # Short structured text: skip all NLP
            resolved = resolve(engine_results)
            if allowed_pii:
                resolved = [e for e in resolved if e.pii_type in allowed_pii]
            return DispatchResult(
                resolved=resolved,
                engine_results=engine_results,
                normalised_text=norm,
            )

        # Build tasks for concurrent engines
        tasks: list[tuple[str, callable, dict]] = []

        if _use_nlp:
            tasks.append(("presidio", self._run_presidio, {"text": working_text}))
            tasks.append(("gliner",   _gliner_engine.run,  {"text": working_text}))

        if _use_otter:
            tasks.append(("otter", _otter_engine.run, {"text": working_text}))

        if _use_llm:
            tasks.append(("llm", _llm_engine.run, {"text": working_text}))

        if parallel and len(tasks) > 1:
            engine_results.extend(self._run_parallel(tasks))
        else:
            for label, fn, kwargs in tasks:
                if label in ("presidio",):
                    # presidio has its own result wrapping
                    er = fn(**kwargs)
                else:
                    er = fn(kwargs.pop("text"), **kwargs)
                engine_results.append(er)

        # ── 4. Entity Resolution ──────────────────────────────────────────────
        resolved = resolve(engine_results)

        # Filter to allowed PII types if specified
        if allowed_pii:
            resolved = [e for e in resolved if e.pii_type in allowed_pii]

        return DispatchResult(
            resolved=resolved,
            engine_results=engine_results,
            normalised_text=norm,
        )

    # ── Parallel execution ────────────────────────────────────────────────────

    def _run_parallel(
        self,
        tasks: list[tuple[str, callable, dict]],
    ) -> list[EngineResult]:
        results: list[EngineResult] = []
        with concurrent.futures.ThreadPoolExecutor(
            max_workers=min(len(tasks), 4),
            thread_name_prefix="pii_engine",
        ) as pool:
            futures = {}
            for label, fn, kwargs in tasks:
                if label == "presidio":
                    fut = pool.submit(fn, **kwargs)
                else:
                    text_val = kwargs.pop("text")
                    fut = pool.submit(fn, text_val, **kwargs)
                futures[fut] = label

            for fut in concurrent.futures.as_completed(futures):
                label = futures[fut]
                try:
                    result = fut.result()
                    results.append(result)
                except Exception as exc:
                    logger.error("[DISPATCHER] Engine %s failed: %s", label, exc)
                    results.append(EngineResult(engine=label, error=str(exc)))

        return results

    # ── Presidio integration (legacy NER, kept for compatibility) ─────────────

    def _run_presidio(self, text: str) -> EngineResult:
        """
        Run the legacy Presidio NER pass and wrap as EngineResult.
        Presidio is a supplementary engine — GLiNER covers the same types
        with higher accuracy, but Presidio adds useful cross-validation.
        """
        try:
            from services.pii_service import _detect_with_presidio
            raw_matches = _detect_with_presidio(text)
            wrapped = [
                PIIMatch(
                    pii_type=m.pii_type,
                    value=m.value,
                    source="presidio",
                    confidence=m.confidence,
                    start=m.start,
                    end=m.end,
                    context="",
                )
                for m in raw_matches
            ]
            return EngineResult(engine="presidio", matches=wrapped)
        except Exception as exc:
            logger.warning("[DISPATCHER] Presidio pass failed: %s", exc)
            return EngineResult(engine="presidio", error=str(exc))


# ── Module-level singleton ─────────────────────────────────────────────────────
_dispatcher = DetectionDispatcher()


def dispatch_detection(
    text: str,
    use_nlp:     bool = True,
    use_llm:     bool = True,
    use_otter:   bool = True,
    parallel:    bool = True,
    allowed_pii: Optional[set[str]] = None,
    doc_type:    str = "generic",
) -> DispatchResult:
    """Module-level convenience wrapper around DetectionDispatcher.dispatch."""
    return _dispatcher.dispatch(
        text=text,
        use_nlp=use_nlp,
        use_llm=use_llm,
        use_otter=use_otter,
        parallel=parallel,
        allowed_pii=allowed_pii,
        doc_type=doc_type,
    )
