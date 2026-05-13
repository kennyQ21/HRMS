"""
services/pii_service.py
------------------------
Public facade for PII detection.

Wraps the detection_dispatcher and post_processor into a simple API
used by tests, scripts and external callers.

Exported functions:
  detect_pii(text, use_nlp, use_llm, allowed_pii, doc_type)
      → DispatchResult (has .matches, .counts, .select_primary())

  select_primary_pii(matches)
      → (pii_type | None, count, score)
"""

from __future__ import annotations

from typing import Optional

from services.detection_dispatcher import dispatch_detection, DispatchResult
from services.entity_resolution import select_primary_from_resolved
from services.entities import PIIMatch
from services.post_processor import post_process


def detect_pii(
    text: str,
    use_nlp:     bool = True,
    use_llm:     bool = True,
    allowed_pii: Optional[set[str]] = None,
    doc_type:    str = "generic",
) -> DispatchResult:
    """
    Run the full PII detection pipeline on *text*.

    Returns a DispatchResult with .matches, .counts, and .select_primary().

    Post-processing (confidence gates, stopword rejection, drug canonicalization)
    is applied inside dispatch_detection → post_processor.

    Args:
        text:        Input text to scan.
        use_nlp:     Enable GLiNER / semantic NER (default True).
        use_llm:     Enable Qwen LLM multilingual engine (default True).
        allowed_pii: Optional whitelist of PII type IDs to return.
        doc_type:    Document type hint for routing (e.g. "image", "pdf").

    Returns:
        DispatchResult with resolved PII entities.
    """
    result = dispatch_detection(
        text=text,
        use_nlp=use_nlp,
        use_llm=use_llm,
        allowed_pii=allowed_pii,
        doc_type=doc_type,
    )

    # Apply post-processing to the resolved entities
    result.resolved = post_process(result.resolved)

    return result


def select_primary_pii(
    matches: list[PIIMatch],
    allowed_types: Optional[set[str]] = None,
) -> tuple[str | None, int, float]:
    """
    Pick the primary (most prominent) PII type from a list of matches.

    Returns (pii_type, count, score).
    Wrapper kept for backward compatibility with test scripts.
    """
    from services.entity_resolution import ResolvedEntity
    from constants import PII_TYPE_MAP

    # Convert PIIMatch → lightweight ResolvedEntity for scoring
    resolved: list[ResolvedEntity] = []
    for m in matches:
        type_info = PII_TYPE_MAP.get(m.pii_type)
        sensitivity = type_info["sensitivity"] if type_info else "Low"
        resolved.append(ResolvedEntity(
            pii_type=m.pii_type,
            value=m.value,
            confidence=m.confidence,
            sources=[m.source],
            sensitivity=sensitivity,
        ))

    return select_primary_from_resolved(resolved, allowed_types)
