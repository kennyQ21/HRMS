"""
services/pii_service.py
------------------------
Thin public API for PII detection — delegates entirely to the dispatcher.

    result = detect_pii(text, use_nlp=True)
    result.counts   → dict[str, int]
    result.matches  → list[PIIMatch]

Presidio has been removed. The pipeline is now:
    Regex → GLiNER → Otter → Qwen LLM → Entity Resolution
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field

from services.engines.base_engine import PIIMatch  # re-export

logger = logging.getLogger(__name__)


@dataclass
class PIIResult:
    """Backward-compatible result wrapper."""
    matches: list[PIIMatch] = field(default_factory=list)

    @property
    def counts(self) -> dict[str, int]:
        out: dict[str, int] = {}
        for m in self.matches:
            out[m.pii_type] = out.get(m.pii_type, 0) + 1
        return out

    @property
    def by_type(self) -> dict[str, list[PIIMatch]]:
        out: dict[str, list[PIIMatch]] = {}
        for m in self.matches:
            out.setdefault(m.pii_type, []).append(m)
        return out


def detect_pii(text: str, use_nlp: bool = True) -> PIIResult:
    """
    Detect PII in *text* using the full engine pipeline.
    Returns a PIIResult with .matches and .counts.
    """
    from services.detection_dispatcher import dispatch_detection
    result = dispatch_detection(text, use_nlp=use_nlp)
    return PIIResult(matches=result.matches)
