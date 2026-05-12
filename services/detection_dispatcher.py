"""
services/detection_dispatcher.py
-----------------------------------
Detection Dispatcher — language-aware engine routing.

Architecture:
  ┌──────────────────────────────────────────────────────┐
  │               Language Detection                      │
  └──────┬──────────────────────────────┬────────────────┘
         │ English                      │ Foreign / Mixed
         ▼                              ▼
  ┌─────────────┐               ┌─────────────────┐
  │   Regex     │               │     Regex        │
  │   GLiNER    │               │  Qwen 0.5B (LLM) │
  └─────────────┘               └─────────────────┘
         │                              │
         └──────────────┬───────────────┘
                        ▼
               Entity Resolution
                        ▼
               Post-Processing

Notes:
- Otter removed: caused massive false positives on narrative/conversational docs
- Presidio removed: replaced by GLiNER with better precision
- LLM (Qwen 0.5B) runs ONLY when non-English or medical text detected
- LLM uses constrained prompts for targeted extraction (no unrestricted hallucination)
"""

from __future__ import annotations

import concurrent.futures
import logging
from dataclasses import dataclass, field
from functools import lru_cache
from typing import Optional

from constants import LLM_PRIORITY_PII, PII_TYPES, SEMANTIC_ONLY_PII
from services.engines.base_engine import EngineResult, PIIMatch
from services.entity_resolution import (
    ResolvedEntity,
    resolve,
    resolved_to_pii_counts,
    select_primary_from_resolved,
)
from services.text_normalizer import NormalisedText, normalise
from services.language_detector import detect as detect_language, LangResult

logger = logging.getLogger(__name__)


@dataclass
class DispatchResult:
    resolved:        list[ResolvedEntity] = field(default_factory=list)
    engine_results:  list[EngineResult]   = field(default_factory=list)
    normalised_text: Optional[NormalisedText] = None
    language:        Optional[LangResult] = None

    @property
    def matches(self) -> list[PIIMatch]:
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


# ── Engine singletons — lazy loaded, one per process ─────────────────────────

@lru_cache(maxsize=1)
def _regex_engine():
    from services.engines.regex_engine import RegexEngine
    return RegexEngine()

@lru_cache(maxsize=1)
def _gliner_engine():
    from services.engines.gliner_engine import GLiNEREngine
    return GLiNEREngine()

@lru_cache(maxsize=1)
def _llm_engine():
    from services.engines.llm_engine import LLMEngine
    return LLMEngine()


# ── Persistent thread pool ────────────────────────────────────────────────────
_ENGINE_POOL = concurrent.futures.ThreadPoolExecutor(
    max_workers=3,
    thread_name_prefix="pii_engine",
)


class DetectionDispatcher:

    def dispatch(
        self,
        text: str,
        allowed_pii: Optional[set[str]] = None,
        doc_type:    str = "generic",
    ) -> DispatchResult:

        if not text or not text.strip():
            return DispatchResult()

        # ── Normalise ─────────────────────────────────────────────────────────
        norm         = normalise(text)
        working_text = norm.normalised
        word_count   = len(working_text.split())

        # ── Language detection ────────────────────────────────────────────────
        lang = detect_language(working_text)

        # ── Engine routing decision ───────────────────────────────────────────
        is_short = word_count < 20

        # GLiNER — English semantic NER.
        # Run ONLY when English content is present. It cannot read Indic,
        # Arabic, CJK or other non-Latin scripts — running it on purely
        # non-English text wastes ~30 seconds and finds nothing.
        use_gliner = lang.is_english and not is_short

        # Qwen LLM — multilingual semantic PII.
        # Run when foreign/Indic script detected OR medical document.
        # Requires Ollama to be running; skips gracefully if not.
        use_llm = (lang.has_foreign or doc_type == "medical") and not is_short

        logger.info(
            "[DISPATCHER] doc_type=%s words=%d | lang=%s "
            "foreign=%s indic=%s | regex=✓ gliner=%s llm=%s",
            doc_type, word_count,
            lang.primary_lang, lang.has_foreign, lang.has_indic,
            "✓" if use_gliner else "✗",
            "✓" if use_llm    else "✗",
        )

        # ── Regex (always synchronous) ────────────────────────────────────────
        # Pass use_nlp=True so regex knows GLiNER will handle semantic types
        engine_results: list[EngineResult] = []
        engine_results.append(
            _regex_engine().run(working_text, use_nlp=True)
        )

        # ── Build parallel tasks ──────────────────────────────────────────────
        tasks: list[tuple[str, object, dict]] = []

        if use_gliner:
            tasks.append(("gliner", _gliner_engine().run, {"text": working_text}))

        if use_llm:
            tasks.append(("llm", _llm_engine().run, {
                "text": working_text,
                "lang": lang,
            }))

        # ── Execute ───────────────────────────────────────────────────────────
        if len(tasks) > 1:
            engine_results.extend(self._run_parallel(tasks))
        elif len(tasks) == 1:
            _label, fn, kwargs = tasks[0]
            text_val = kwargs.pop("text")
            engine_results.append(fn(text_val, **kwargs))

        # ── Entity Resolution ─────────────────────────────────────────────────
        resolved = resolve(engine_results)
        if allowed_pii:
            resolved = [e for e in resolved if e.pii_type in allowed_pii]

        return DispatchResult(
            resolved=resolved,
            engine_results=engine_results,
            normalised_text=norm,
            language=lang,
        )

    def _run_parallel(self, tasks: list[tuple]) -> list[EngineResult]:
        results:  list[EngineResult] = []
        futures:  dict = {}
        for label, fn, kwargs in tasks:
            text_val = kwargs.pop("text")
            futures[_ENGINE_POOL.submit(fn, text_val, **kwargs)] = label

        for fut in concurrent.futures.as_completed(futures):
            label = futures[fut]
            try:
                results.append(fut.result())
            except Exception as exc:
                logger.error("[DISPATCHER] %s engine failed: %s", label, exc)
                results.append(EngineResult(engine=label, error=str(exc)))
        return results


# ── Module singleton ──────────────────────────────────────────────────────────
_dispatcher = DetectionDispatcher()


def dispatch_detection(
    text: str,
    # Legacy keyword args kept for call-site compatibility — ignored internally
    use_nlp:     bool = True,
    use_llm:     bool = True,
    use_otter:   bool = False,   # Otter removed
    parallel:    bool = True,
    allowed_pii: Optional[set[str]] = None,
    doc_type:    str = "generic",
) -> DispatchResult:
    """
    Run the full detection pipeline on *text*.

    Engine routing is automatic based on language detection:
      English            → Regex + GLiNER
      Non-English/Indic  → Regex + Qwen 0.5B
      Mixed              → Regex + GLiNER + Qwen 0.5B
      Medical (any lang) → includes Qwen 0.5B
    """
    return _dispatcher.dispatch(
        text=text,
        allowed_pii=allowed_pii,
        doc_type=doc_type,
    )
