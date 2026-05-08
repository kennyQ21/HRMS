"""
services/pii_service.py
------------------------
Public API for PII detection.

This module is the stable interface consumed by all routers.
Internally it delegates to the new multi-engine Detection Dispatcher,
while preserving 100% backward compatibility with the existing call sites:

    result = detect_pii(text, use_nlp=True)
    result.counts   → dict[str, int]
    result.matches  → list[PIIMatch]

Architecture reference (see full spec):
  Regex → GLiNER → Otter → Qwen/LLM → Entity Resolution → PIIResult

Legacy Presidio NER is retained as a supplementary cross-validation engine
inside the dispatcher, and the old _detect_with_presidio() function is kept
here so the dispatcher can import it without circular dependencies.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from functools import lru_cache
from typing import TYPE_CHECKING, Any, Optional

from constants import PII_TYPES, PII_TYPE_MAP

if TYPE_CHECKING:
    from presidio_analyzer import AnalyzerEngine, PatternRecognizer, RecognizerResult

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────────────────────
# Backward-compatible data model
# (The dispatcher uses its own PIIMatch; we re-export it here for routers that
#  import directly from pii_service.)
# ─────────────────────────────────────────────────────────────────────────────

from services.engines.base_engine import PIIMatch  # re-export


@dataclass
class PIIResult:
    """Backward-compatible result wrapper returned by detect_pii()."""
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


# ─────────────────────────────────────────────────────────────────────────────
# Presidio legacy NER — kept for cross-validation inside the dispatcher
# ─────────────────────────────────────────────────────────────────────────────

_PRESIDIO_TO_INTERNAL: dict[str, str] = {
    "PERSON":        "name",
    "PHONE_NUMBER":  "phone",
    "CREDIT_CARD":   "credit_card",
    "LOCATION":      "address",
    "IP_ADDRESS":    "ip_address",
    "IN_PAN":        "pan",
    "IN_AADHAAR":    "aadhaar",
    "IN_VOTER":      "voter_id",
    "ORGANIZATION":  "organization",
}

_MIN_PRESIDIO_SCORE: float = 0.50
_PRESIDIO_MIN_BY_TYPE: dict[str, float] = {
    "name": 0.65, "address": 0.60, "phone": 0.50,
}


def _patch_tldextract_for_presidio() -> None:
    try:
        import tldextract as _tldextract
    except ImportError:
        return
    _offline = _tldextract.TLDExtract(suffix_list_urls=(), fallback_to_snapshot=True)
    _tldextract.extract = _offline
    _tldextract.TLDExtract = lambda **kw: _offline  # type: ignore


def _pan_recognizer() -> "PatternRecognizer":
    from presidio_analyzer import Pattern, PatternRecognizer
    return PatternRecognizer(
        supported_entity="IN_PAN",
        patterns=[Pattern("PAN", r"\b[A-Z]{5}[0-9]{4}[A-Z]\b", 0.85)],
        context=["pan", "permanent", "account"],
    )


def _aadhaar_recognizer() -> "PatternRecognizer":
    from presidio_analyzer import Pattern, PatternRecognizer
    return PatternRecognizer(
        supported_entity="IN_AADHAAR",
        patterns=[Pattern("AADHAAR", r"\b\d{4}\s?\d{4}\s?\d{4}\b", 0.65)],
        context=["aadhaar", "uid", "unique", "identification"],
    )


def _voter_recognizer() -> "PatternRecognizer":
    from presidio_analyzer import Pattern, PatternRecognizer
    return PatternRecognizer(
        supported_entity="IN_VOTER",
        patterns=[Pattern("VOTER_ID", r"\b[A-Z]{3}[0-9]{7}\b", 0.80)],
        context=["voter", "epic", "election"],
    )


@lru_cache(maxsize=1)
def _get_presidio_analyzer() -> "AnalyzerEngine":
    _patch_tldextract_for_presidio()
    from presidio_analyzer import AnalyzerEngine
    from presidio_analyzer.nlp_engine import NlpEngineProvider

    logger.info("Initialising Presidio with en_core_web_sm…")
    nlp_engine = NlpEngineProvider(nlp_configuration={
        "nlp_engine_name": "spacy",
        "models": [{"lang_code": "en", "model_name": "en_core_web_sm"}],
    }).create_engine()
    engine = AnalyzerEngine(nlp_engine=nlp_engine)
    registry = engine.registry
    try:
        registry.remove_recognizer("EmailRecognizer")
    except Exception:
        pass
    registry.add_recognizer(_pan_recognizer())
    registry.add_recognizer(_aadhaar_recognizer())
    registry.add_recognizer(_voter_recognizer())
    logger.info("Presidio ready.")
    return engine


def _is_weak_presidio_match(pii_type: str, value: str) -> bool:
    normalized = re.sub(r"\s+", " ", value).strip()
    lowered = normalized.lower()
    if not normalized:
        return True
    if pii_type == "name":
        if any(ch.isdigit() for ch in normalized):
            return True
        tokens = [t for t in re.split(r"[\s\-]+", lowered) if t]
        if len(tokens) < 2:
            return True
        disallowed = {"road", "street", "nagar", "colony", "temple", "address",
                      "government", "india", "authority", "commission", "department",
                      "aadhaar", "card", "uid"}
        return any(t in disallowed for t in tokens)
    if pii_type == "address":
        if len(normalized) < 10:
            return True
        markers = ("address", "road", "street", "lane", "nagar", "colony",
                   "avenue", "sector", "block", "village", "city", ",")
        return not any(m in lowered for m in markers) and not any(
            ch.isdigit() for ch in normalized
        )
    return False


def _detect_with_presidio(text: str) -> list[PIIMatch]:
    """Run legacy Presidio NER. Called by DetectionDispatcher for cross-validation."""
    try:
        analyzer = _get_presidio_analyzer()
        results: list["RecognizerResult"] = analyzer.analyze(
            text=text, language="en", score_threshold=_MIN_PRESIDIO_SCORE,
        )
    except Exception as exc:
        logger.warning("Presidio analysis failed: %s", exc)
        return []

    matches: list[PIIMatch] = []
    for r in results:
        internal_id = _PRESIDIO_TO_INTERNAL.get(r.entity_type)
        if not internal_id:
            continue
        min_score = _PRESIDIO_MIN_BY_TYPE.get(internal_id, _MIN_PRESIDIO_SCORE)
        if r.score < min_score:
            continue
        raw_value = re.sub(r"\s+", " ", text[r.start:r.end]).strip()
        if _is_weak_presidio_match(internal_id, raw_value):
            continue
        matches.append(PIIMatch(
            pii_type=internal_id,
            value=raw_value,
            source="presidio",
            confidence=r.score,
            start=r.start,
            end=r.end,
        ))
    return matches


# ─────────────────────────────────────────────────────────────────────────────
# Public API
# ─────────────────────────────────────────────────────────────────────────────

def detect_pii(
    text: str,
    use_nlp: bool = True,
    presidio_entities: Optional[list[str]] = None,
    use_llm: bool = True,
    use_otter: bool = True,
    allowed_pii: Optional[set[str]] = None,
    doc_type: str = "generic",
) -> PIIResult:
    """
    Hybrid PII detection pipeline — public entry point.

    Delegates to DetectionDispatcher which runs:
      Regex → GLiNER → Otter → Qwen/LLM → Presidio → Entity Resolution

    Args:
        text:              Text to scan.
        use_nlp:           Enable GLiNER + Presidio (default True).
                           Set False for short structured DB column values.
        presidio_entities: Legacy argument — ignored (Presidio runs as a
                           supplementary engine inside the dispatcher).
        use_llm:           Enable Ollama/Qwen engine (default True).
        use_otter:         Enable Otter structural extractor (default True).
        allowed_pii:       Restrict to these MASTER_PIIS type IDs.
        doc_type:          Routing hint: "medical"|"financial"|"hr"|"generic".

    Returns:
        PIIResult with .matches and .counts.
    """
    from services.detection_dispatcher import dispatch_detection

    if not text or not text.strip():
        return PIIResult()

    dispatch_result = dispatch_detection(
        text=text,
        use_nlp=use_nlp,
        use_llm=use_llm,
        use_otter=use_otter,
        allowed_pii=allowed_pii,
        doc_type=doc_type,
    )

    return PIIResult(matches=dispatch_result.matches)


def select_primary_pii(
    matches: list[PIIMatch],
    allowed_types: Optional[set[str]] = None,
) -> tuple[str | None, int, float]:
    """
    Backward-compatible wrapper around entity_resolution.select_primary_from_resolved.
    Called by scans.py / files.py which still pass a flat PIIMatch list.
    """
    from services.entity_resolution import (
        EngineResult,
        resolve,
        select_primary_from_resolved,
    )

    if not matches:
        return None, 0, 0.0

    # Wrap in a synthetic EngineResult so resolution can run
    synthetic = EngineResult(engine="legacy", matches=list(matches))
    resolved  = resolve([synthetic])
    return select_primary_from_resolved(resolved, allowed_types)


def pii_result_to_entities(result: PIIResult) -> dict[str, list[dict[str, Any]]]:
    """Convert PIIResult to the OCR extraction JSON shape."""
    _INTERNAL_TO_ENTITY_TYPE: dict[str, str] = {
        "name": "PERSON", "address": "LOCATION", "pan": "PAN",
        "aadhaar": "AADHAAR", "voter_id": "VOTER_ID", "phone": "PHONE_NUMBER",
        "email": "EMAIL", "credit_card": "CREDIT_CARD", "dob": "DOB",
        "expiry": "EXPIRY", "cvv": "CVV", "ip_address": "IP_ADDRESS",
        "diagnosis": "DIAGNOSIS", "allergies": "ALLERGIES",
        "prescription": "PRESCRIPTION", "occupation": "OCCUPATION",
        "bank_account": "BANK_ACCOUNT", "upi": "UPI",
        "passport": "PASSPORT", "ssn": "SSN",
    }
    entities: list[dict[str, Any]] = []
    for match in result.matches:
        entities.append({
            "type":   _INTERNAL_TO_ENTITY_TYPE.get(match.pii_type, match.pii_type.upper()),
            "value":  match.value,
            "start":  match.start,
            "end":    match.end,
            "score":  round(match.confidence, 4),
            "source": match.source,
        })
    return {"entities": entities}


def extract_pii_entities(
    text: str,
    use_nlp: bool = True,
    presidio_entities: Optional[list[str]] = None,
) -> dict[str, list[dict[str, Any]]]:
    """Simple production wrapper for OCR pipelines."""
    return pii_result_to_entities(detect_pii(text, use_nlp=use_nlp))
