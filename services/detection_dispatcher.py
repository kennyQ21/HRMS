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
from services.entities import PIIMatch
from services.engines.base_engine import EngineResult
from services.entity_resolution import (
    ResolvedEntity,
    resolve,
    resolved_to_pii_counts,
    select_primary_from_resolved,
)
from services.text_normalizer import NormalisedText, normalise
from services.language_detector import (
    detect as detect_language, LangResult,
    INDIC_SCRIPTS, ARABIC_SCRIPTS, CJK_SCRIPTS,
)

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

@lru_cache(maxsize=1)
def _qwen_ner_engine():
    from services.engines.qwen_ner_engine import QwenNEREngine
    return QwenNEREngine()


# ── Persistent thread pool ────────────────────────────────────────────────────
_ENGINE_POOL = concurrent.futures.ThreadPoolExecutor(
    max_workers=2,
    thread_name_prefix="pii_engine",
)


class DetectionDispatcher:
    """
    Language-aware detection dispatcher.

    Routing:
      Latin-script only    -> Regex + GLiNER
      Indic/Arabic only    -> Regex + Qwen NER
      Mixed script         -> Regex + GLiNER + Qwen NER
      Short text (<20w)    -> Regex only
    """

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

        # ── Language / script detection ────────────────────────────────────────
        lang = detect_language(working_text)

        # ── Engine routing based on script ────────────────────────────────────
        # Indian ID cards (Aadhaar, PAN, Voter) have very few words (sometimes < 15)
        # but still need full semantic detection. Only skip NLP for truly tiny texts.
        is_short = word_count < 6

        # GLiNER: strong for Latin-script (English-dominant training)
        # Also run for mixed-script docs (Indian IDs often have both scripts)
        use_gliner = (
            not is_short
            and (lang.dominant_script == "latin"
                 or lang.is_multilingual
                 or lang.mixed_script_ratio > 0.10)
        )

        # Qwen NER: constrained extraction for Indic/Arabic/CJK
        # ONLY for non-Latin scripts where GLiNER is weak.
        # Uses constrained prompts — NOT generative extraction.
        # All outputs pass span_grounding() before acceptance.
        use_qwen_ner = (
            not is_short
            and (lang.has_indic or lang.has_arabic or lang.has_cjk
                 or lang.dominant_script in INDIC_SCRIPTS | ARABIC_SCRIPTS | CJK_SCRIPTS)
        )

        semantic_task = None
        if use_qwen_ner:
            semantic_task = ("qwen_ner", _qwen_ner_engine().run, {"text": working_text, "lang": lang})
        elif use_gliner:
            semantic_task = ("gliner", _gliner_engine().run, {"text": working_text})

        logger.info(
            "[DISPATCHER] doc_type=%s words=%d | script=%s mixed=%.2f "
            "indic=%s arabic=%s cjk=%s | regex=✓ semantic=%s",
            doc_type, word_count,
            lang.dominant_script, lang.mixed_script_ratio,
            lang.has_indic, lang.has_arabic, lang.has_cjk,
            semantic_task[0] if semantic_task else "none",
        )

        # ── Safe parallelization: regex + at most ONE semantic engine ─────────
        tasks: list[tuple[str, object, dict]] = [
            ("regex", _regex_engine().run, {"text": working_text, "use_nlp": True})
        ]
        if semantic_task:
            tasks.append(semantic_task)

        # ── Execute ───────────────────────────────────────────────────────────
        if len(tasks) > 1:
            engine_results = self._run_parallel(tasks)
        else:
            _label, fn, kwargs = tasks[0]
            text_val = kwargs.pop("text")
            engine_results = [fn(text_val, **kwargs)]

        # ── Entity Resolution + Span Grounding ───────────────────────────────
        resolved = resolve(engine_results, source_text=working_text)
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
            call_kwargs = dict(kwargs)
            text_val = call_kwargs.pop("text")
            futures[_ENGINE_POOL.submit(fn, text_val, **call_kwargs)] = label

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
