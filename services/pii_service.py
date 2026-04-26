"""
services/pii_service.py
-----------------------
Hybrid PII detection pipeline.

Layer 1 — Regex   : fast, deterministic — email, phone, PAN, Aadhaar, CC …
Layer 2 — Presidio: context-aware NER  — PERSON, LOCATION, ORGANIZATION …
Layer 3 — Merge   : deduplicate & return unified PIIResult

Entry point:
    result = detect_pii(text, use_nlp=True)
    result.counts    → dict[str, int]   used by existing scan logic
    result.by_type   → dict[str, list[PIIMatch]]
    result.matches   → list[PIIMatch]

Performance notes:
  • tldextract is patched before lazy Presidio initialisation to prevent a
    public-suffix-list download on first NLP run.
  • EmailRecognizer is removed from Presidio's registry — it uses tldextract
    internally and our regex layer covers email with equal accuracy.
  • The AnalyzerEngine is @lru_cached — NLP models load exactly once per
    process (~1–2 s), then every subsequent call is fast.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from functools import lru_cache
from typing import TYPE_CHECKING, Any, Optional

from constants import PII_TYPES

if TYPE_CHECKING:
    from presidio_analyzer import AnalyzerEngine, PatternRecognizer, RecognizerResult

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────────────────────
# Data model
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class PIIMatch:
    pii_type:   str    # internal id — "email", "pan", "name", …
    value:      str    # matched text
    source:     str    # "regex" | "presidio"
    confidence: float  # 0.0 – 1.0
    start:      int = -1
    end:        int = -1


@dataclass
class PIIResult:
    matches: list[PIIMatch] = field(default_factory=list)

    @property
    def counts(self) -> dict[str, int]:
        """Returns {pii_type: match_count} — consumed by existing scan logic."""
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


_INTERNAL_TO_ENTITY_TYPE: dict[str, str] = {
    "name": "PERSON",
    "address": "LOCATION",
    "pan": "PAN",
    "aadhaar": "AADHAAR",
    "voter_id": "VOTER_ID",
    "phone": "PHONE_NUMBER",
    "email": "EMAIL",
    "credit_card": "CREDIT_CARD",
    "dob": "DOB",
    "expiry": "EXPIRY",
    "cvv": "CVV",
    "ip_address": "IP_ADDRESS",
}


# ─────────────────────────────────────────────────────────────────────────────
# Presidio entity → internal PII id mapping
# Only entities in this map are surfaced; everything else is discarded.
# ─────────────────────────────────────────────────────────────────────────────

_PRESIDIO_TO_INTERNAL: dict[str, str] = {
    "PERSON":        "name",
    "PHONE_NUMBER":  "phone",       # keep — Presidio is better at intl formats
    "CREDIT_CARD":   "credit_card",
    "LOCATION":      "address",
    "IP_ADDRESS":    "ip_address",
    # India-specific — added via custom recognizers below
    "IN_PAN":        "pan",
    "IN_AADHAAR":    "aadhaar",
    "IN_VOTER":      "voter_id",
}

# Presidio hits below this score are discarded (noise filter)
_MIN_SCORE: float = 0.50

_PRESIDIO_MIN_SCORE_BY_TYPE: dict[str, float] = {
    "name": 0.65,
    "address": 0.60,
    "phone": 0.50,
    "email": 0.50,
}

# When NLP is enabled, prefer Presidio for these weak/ambiguous free-text types.
_PRESIDIO_PREFERRED_TYPES: set[str] = {"address", "name"}

_DEDUPE_BY_VALUE_TYPES: set[str] = {
    "aadhaar",
    "pan",
    "phone",
    "email",
    "credit_card",
    "voter_id",
    "name",
    "address",
}

_PII_PRIORITY: dict[str, int] = {
    "aadhaar": 10,
    "pan": 10,
    "credit_card": 10,
    "voter_id": 9,
    "phone": 8,
    "email": 8,
    "address": 6,
    "name": 3,
    "expiry": 2,
    "dob": 2,
    "cvv": 1,
}


# ─────────────────────────────────────────────────────────────────────────────
# Custom recognizers for India-specific PII (not in Presidio's default set)
# ─────────────────────────────────────────────────────────────────────────────

def _pan_recognizer() -> "PatternRecognizer":
    """PAN: 5 uppercase letters + 4 digits + 1 uppercase letter."""
    from presidio_analyzer import Pattern, PatternRecognizer

    return PatternRecognizer(
        supported_entity="IN_PAN",
        patterns=[Pattern("PAN", r"\b[A-Z]{5}[0-9]{4}[A-Z]\b", 0.85)],
        context=["pan", "permanent", "account", "income", "tax"],
    )


def _aadhaar_recognizer() -> "PatternRecognizer":
    """Aadhaar: 12 digits, optional spaces every 4 digits.
    Score boosted by context keywords to reduce false positives on generic
    12-digit numbers (transaction IDs, part numbers, etc.)."""
    from presidio_analyzer import Pattern, PatternRecognizer

    return PatternRecognizer(
        supported_entity="IN_AADHAAR",
        patterns=[Pattern("AADHAAR", r"\b\d{4}\s?\d{4}\s?\d{4}\b", 0.65)],
        context=["aadhaar", "uid", "unique", "identification", "aadhar"],
    )


def _voter_recognizer() -> "PatternRecognizer":
    """Voter ID: 3 uppercase letters + 7 digits."""
    from presidio_analyzer import Pattern, PatternRecognizer

    return PatternRecognizer(
        supported_entity="IN_VOTER",
        patterns=[Pattern("VOTER_ID", r"\b[A-Z]{3}[0-9]{7}\b", 0.80)],
        context=["voter", "epic", "election"],
    )


# ─────────────────────────────────────────────────────────────────────────────
# Presidio engine — loaded once per process
# ─────────────────────────────────────────────────────────────────────────────

def _patch_tldextract_for_presidio() -> None:
    try:
        import tldextract as _tldextract
    except ImportError:
        return

    _offline_extractor = _tldextract.TLDExtract(
        suffix_list_urls=(),
        fallback_to_snapshot=True,
    )
    _tldextract.extract = _offline_extractor
    _tldextract.TLDExtract = lambda **kw: _offline_extractor  # type: ignore


@lru_cache(maxsize=1)
def _get_analyzer() -> "AnalyzerEngine":
    """
    Initialise AnalyzerEngine explicitly using en_core_web_sm (already
    installed, 12 MB). Without this, Presidio defaults to en_core_web_lg
    which triggers a 400 MB download on first run.

    Also removes EmailRecognizer (uses tldextract → network calls).
    Email is handled more accurately by our regex layer anyway.
    """
    _patch_tldextract_for_presidio()

    try:
        from presidio_analyzer import AnalyzerEngine
        from presidio_analyzer.nlp_engine import NlpEngineProvider
    except ImportError as exc:
        raise RuntimeError(
            "Presidio NLP detection requires presidio-analyzer, spacy, and an English spaCy model. "
            "Install project requirements before calling detect_pii(..., use_nlp=True)."
        ) from exc

    logger.info("Initialising Presidio with en_core_web_sm (no download needed)…")

    # Explicitly configure the small spaCy model — already installed
    nlp_engine = NlpEngineProvider(nlp_configuration={
        "nlp_engine_name": "spacy",
        "models": [{"lang_code": "en", "model_name": "en_core_web_sm"}],
    }).create_engine()

    engine = AnalyzerEngine(nlp_engine=nlp_engine)
    registry = engine.registry

    # Remove EmailRecognizer — triggers tldextract network download.
    # Our regex layer handles email with equal accuracy, zero network cost.
    try:
        registry.remove_recognizer("EmailRecognizer")
    except Exception:
        pass

    # Add India-specific recognizers
    registry.add_recognizer(_pan_recognizer())
    registry.add_recognizer(_aadhaar_recognizer())
    registry.add_recognizer(_voter_recognizer())

    logger.info("Presidio ready — model: en_core_web_sm | custom: IN_PAN, IN_AADHAAR, IN_VOTER")
    return engine


# ─────────────────────────────────────────────────────────────────────────────
# Compiled regex patterns from constants.py (compiled once at import time)
# ─────────────────────────────────────────────────────────────────────────────

_REGEX_PATTERNS: dict[str, re.Pattern] = {
    p["id"]: re.compile(p["regex"])
    for p in PII_TYPES
    if "regex" in p
}


# ─────────────────────────────────────────────────────────────────────────────
# Layer 1 — Regex
# ─────────────────────────────────────────────────────────────────────────────

def _detect_with_regex(text: str, exclude_types: Optional[set[str]] = None) -> list[PIIMatch]:
    def _digits_only(value: str) -> str:
        return re.sub(r"\D", "", value)

    def _is_luhn_valid(value: str) -> bool:
        if not value.isdigit() or len(value) < 13:
            return False
        total = 0
        reverse_digits = value[::-1]
        for idx, digit_char in enumerate(reverse_digits):
            digit = int(digit_char)
            if idx % 2 == 1:
                digit *= 2
                if digit > 9:
                    digit -= 9
            total += digit
        return total % 10 == 0

    matches: list[PIIMatch] = []
    for pii_id, pattern in _REGEX_PATTERNS.items():
        if exclude_types and pii_id in exclude_types:
            continue
        for m in pattern.finditer(text):
            value = m.group().strip()

            if pii_id == "credit_card":
                cc_digits = _digits_only(value)
                if not _is_luhn_valid(cc_digits):
                    continue
                value = cc_digits
            elif pii_id in {"phone", "aadhaar"}:
                value = _digits_only(value) or value

            matches.append(PIIMatch(
                pii_type=pii_id,
                value=value,
                source="regex",
                confidence=1.0,  # regex is deterministic
                start=m.start(),
                end=m.end(),
            ))
    return matches


# ─────────────────────────────────────────────────────────────────────────────
# Layer 2 — Presidio NER
# ─────────────────────────────────────────────────────────────────────────────

def _detect_with_presidio(
    text: str,
    entities: Optional[list[str]] = None,
) -> list[PIIMatch]:
    analyzer = _get_analyzer()
    try:
        results: list["RecognizerResult"] = analyzer.analyze(
            text=text,
            language="en",
            entities=entities,
            score_threshold=_MIN_SCORE,
        )
    except Exception as exc:
        logger.warning("Presidio analysis failed: %s", exc)
        return []

    def _normalize_text(value: str) -> str:
        return re.sub(r"\s+", " ", value).strip()

    def _is_weak_presidio_match(pii_type: str, value: str) -> bool:
        normalized = _normalize_text(value)
        lowered = normalized.lower()
        if not normalized:
            return True

        if pii_type == "name":
            if any(ch.isdigit() for ch in normalized):
                return True
            tokens = [t for t in re.split(r"[\s\-]+", lowered) if t]
            if len(tokens) < 2:
                return True
            disallowed = {
                "road", "street", "nagar", "colony", "temple", "address",
                "government", "india", "authority", "commission", "department",
                "aadhaar", "card", "uid",
            }
            if any(token in disallowed for token in tokens):
                return True
            return False

        if pii_type == "address":
            if len(normalized) < 10:
                return True
            markers = (
                "address", "road", "street", "lane", "nagar", "colony", "avenue",
                "sector", "block", "village", "city", ",",
            )
            if not any(marker in lowered for marker in markers) and not any(ch.isdigit() for ch in normalized):
                return True
            return False

        return False

    matches: list[PIIMatch] = []
    for r in results:
        internal_id = _PRESIDIO_TO_INTERNAL.get(r.entity_type)
        if not internal_id:
            continue
        min_score = _PRESIDIO_MIN_SCORE_BY_TYPE.get(internal_id, _MIN_SCORE)
        if r.score < min_score:
            continue
        raw_value = text[r.start:r.end]
        if _is_weak_presidio_match(internal_id, raw_value):
            continue
        matches.append(PIIMatch(
            pii_type=internal_id,
            value=_normalize_text(raw_value),
            source="presidio",
            confidence=r.score,
            start=r.start,
            end=r.end,
        ))
    return matches


# ─────────────────────────────────────────────────────────────────────────────
# Layer 3 — Merge + deduplicate
# ─────────────────────────────────────────────────────────────────────────────

def _merge(
    regex_matches: list[PIIMatch],
    presidio_matches: list[PIIMatch],
) -> list[PIIMatch]:
    """
    Combine both layers without double-counting.

    Rules:
    1. All regex hits are kept (high precision for structured patterns).
    2. A Presidio hit is DROPPED if a regex match already covers the same
       character span AND same pii_type.
    3. A Presidio hit is DROPPED if any regex match of the same type
       overlaps the same span (prevents email counted twice).
    4. Presidio-only entities (PERSON, LOCATION …) are always added.
    """
    merged = list(regex_matches)

    regex_spans = {
        (m.pii_type, m.start, m.end)
        for m in regex_matches if m.start >= 0
    }

    for pm in presidio_matches:
        # Exact span already covered by regex?
        if (pm.pii_type, pm.start, pm.end) in regex_spans:
            continue
        # Overlapping span of same type already covered?
        overlapped = any(
            rm.pii_type == pm.pii_type
            and rm.start >= 0
            and not (pm.end <= rm.start or pm.start >= rm.end)
            for rm in regex_matches
        )
        if overlapped:
            continue
        merged.append(pm)

    deduped: list[PIIMatch] = []
    seen_spans: set[tuple[str, int, int]] = set()
    seen_values: set[tuple[str, str]] = set()

    for match in merged:
        if match.start >= 0:
            span_key = (match.pii_type, match.start, match.end)
            if span_key in seen_spans:
                continue
            seen_spans.add(span_key)

        if match.pii_type in _DEDUPE_BY_VALUE_TYPES:
            normalized = re.sub(r"\W+", "", match.value).lower()
            if normalized:
                value_key = (match.pii_type, normalized)
                if value_key in seen_values:
                    continue
                seen_values.add(value_key)

        deduped.append(match)

    return deduped


def select_primary_pii(
    matches: list[PIIMatch],
    allowed_types: Optional[set[str]] = None,
) -> tuple[str | None, int, float]:
    """
    Pick primary PII using sensitivity-first priority and confidence tie-breaks.
    """
    stats: dict[str, dict[str, float]] = {}
    for match in matches:
        if allowed_types and match.pii_type not in allowed_types:
            continue
        entry = stats.setdefault(match.pii_type, {"count": 0.0, "conf_sum": 0.0})
        entry["count"] += 1
        entry["conf_sum"] += max(0.0, min(1.0, match.confidence))

    if not stats:
        return None, 0, 0.0

    best_type: str | None = None
    best_count = 0
    best_score = -1.0
    best_priority = 0

    for pii_type, entry in stats.items():
        count = int(entry["count"])
        avg_conf = entry["conf_sum"] / count if count else 0.0
        priority = _PII_PRIORITY.get(pii_type, 1)
        score = count * avg_conf

        if (
            priority > best_priority
            or (priority == best_priority and score > best_score)
            or (priority == best_priority and score == best_score and count > best_count)
        ):
            best_type = pii_type
            best_count = count
            best_score = score
            best_priority = priority

    return best_type, best_count, (best_score * best_priority)


# ─────────────────────────────────────────────────────────────────────────────
# Public API
# ─────────────────────────────────────────────────────────────────────────────

def detect_pii(
    text: str,
    use_nlp: bool = True,
    presidio_entities: Optional[list[str]] = None,
) -> PIIResult:
    """
    Run the full hybrid PII detection pipeline.

    Args:
        text:               Text to scan (post-OCR or raw).
        use_nlp:            Enable Presidio NER (default True).
                            Set False for short structured strings (DB columns)
                            where NLP adds latency with minimal benefit.
        presidio_entities:  Restrict Presidio to specific entity types.
                            None = all mapped types.

    Returns:
        PIIResult with .matches, .counts, and .by_type helpers.

    When to use use_nlp=False (regex only):
        - DB column values (short, structured)
        - High-throughput scanning of millions of rows

    When to use use_nlp=True (full hybrid):
        - Document text (Word, PDF, OCR output)
        - Free-form text fields
        - Any text long enough for context to matter (>50 words)
    """
    if not text or not text.strip():
        return PIIResult()

    regex_exclude: set[str] = _PRESIDIO_PREFERRED_TYPES if use_nlp else set()
    regex_matches = _detect_with_regex(text, exclude_types=regex_exclude)

    presidio_matches: list[PIIMatch] = []
    if use_nlp:
        presidio_matches = _detect_with_presidio(text, entities=presidio_entities)

    merged = _merge(regex_matches, presidio_matches)

    logger.debug(
        "detect_pii: %d regex + %d presidio → %d merged",
        len(regex_matches), len(presidio_matches), len(merged),
    )
    return PIIResult(matches=merged)


def pii_result_to_entities(result: PIIResult) -> dict[str, list[dict[str, Any]]]:
    """
    Convert internal PIIResult into the OCR extraction JSON shape:

        {"entities": [{"type": "EMAIL", "value": "...", ...}]}
    """
    entities: list[dict[str, Any]] = []
    for match in result.matches:
        entities.append({
            "type": _INTERNAL_TO_ENTITY_TYPE.get(match.pii_type, match.pii_type.upper()),
            "value": match.value,
            "start": match.start,
            "end": match.end,
            "score": round(match.confidence, 4),
            "source": match.source,
        })
    return {"entities": entities}


def extract_pii_entities(
    text: str,
    use_nlp: bool = True,
    presidio_entities: Optional[list[str]] = None,
) -> dict[str, list[dict[str, Any]]]:
    """
    Extract PII from OCR/raw text and return JSON-serializable entities.

    This is the simple production-facing wrapper for OCR pipelines:
    regex catches structured PII deterministically, while Presidio adds
    contextual entities such as PERSON, LOCATION, and ORGANIZATION when
    use_nlp=True.
    """
    return pii_result_to_entities(
        detect_pii(
            text=text,
            use_nlp=use_nlp,
            presidio_entities=presidio_entities,
        )
    )
