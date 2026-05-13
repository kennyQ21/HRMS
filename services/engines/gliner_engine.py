"""
services/engines/gliner_engine.py
-----------------------------------
Layer 2: GLiNER Semantic NER Engine.

GLiNER (Generalist Named Entity Recognition) uses a single encoder model
that can detect arbitrary entity types at inference time — no fine-tuning
required. This makes it ideal for:
  - Person names, organisation names
  - Occupations, nationalities, locations (city/address)
  - Medical entities: diagnosis, allergy, prescription
  - Educational qualifications
  - Fuzzy / OCR-distorted entities

Model is lazy-loaded once per process via @lru_cache.
Falls back gracefully if GLiNER is not installed or model load fails.

GLiNER label → internal PII id mapping is defined in GLINER_LABEL_MAP below.
"""

from __future__ import annotations

import logging
import re
from functools import lru_cache
from typing import Any, Optional

from services.entities import PIIMatch
from services.utils.timeout import run_with_timeout
from constants import GLINER_TIMEOUT_SECONDS
from .base_engine import BaseEngine

logger = logging.getLogger(__name__)

# Default model — balanced quality vs memory (~370 MB on disk)
_GLINER_MODEL_ID = "urchade/gliner_mediumv2.1"

# Per-type minimum confidence for the 6 semantic types only.
# Removed types are no longer routed through GLiNER.
_PER_TYPE_MIN_SCORE: dict[str, float] = {
    "name":                    0.70,
    "father_name":             0.65,
    "organization":            0.70,
    "diagnosis":               0.80,
    "address":                 0.65,
    "allergies":               0.72,
    "treatment_history":       0.70,
}

_OCR_PER_TYPE_MIN_SCORE: dict[str, float] = {
    "name":                    0.25,   # lower threshold for OCR-fragmented ID card names
    "father_name":             0.25,   # Indian ID cards: S/O names often borderline
    "organization":            0.40,
    "address":                 0.35,
    "diagnosis":               0.55,
    "allergies":               0.55,
    "treatment_history":       0.55,
}

_DEFAULT_MIN_SCORE: float = 0.70   # raised floor — fewer types, higher bar

# Single-token stopwords that GLiNER must never emit as names
_NAME_STOPWORDS: frozenset[str] = frozenset({
    "yes", "no", "sure", "okay", "ok", "yeah", "yep", "nope",
    "right", "correct", "exactly", "absolutely", "definitely", "well",
    "patient", "patients", "client", "clients", "respondent", "respondents",
    "individual", "individuals", "person", "people", "member", "members",
    "user", "users", "employee", "employees", "staff",
    "interviewer", "interviewee", "speaker", "narrator", "host", "guest",
    "doctor", "nurse", "physician", "pharmacist", "provider", "prescriber",
    "i", "me", "my", "we", "our", "you", "your", "they", "them", "their",
    "it", "he", "she", "him", "her", "this", "that",
})

# Maps GLiNER natural-language labels → internal PII ids
# REDUCED SCOPE: Only high-value semantic types that regex cannot detect.
GLINER_LABEL_MAP: dict[str, str] = {
    # Personal — regex cannot detect names
    "person":                       "name",
    "person name":                  "name",
    "full name":                    "name",
    "indian name":                  "name",
    # Father / guardian name on Indian ID documents
    "father name":                  "father_name",
    "father's name":                "father_name",
    "guardian name":                "father_name",
    "relation name":                "father_name",
    # Organisations — regex cannot detect org names
    "organization":                 "organization",
    "company":                      "organization",
    "institution":                  "organization",
    "hospital":                     "organization",
    # Address — regex has label-gated address but GLiNER catches more
    "location":                     "address",
    "address":                      "address",
    "street address":               "address",
    # Medical — high compliance value, regex cannot detect these
    "medical condition":            "diagnosis",
    "diagnosis":                    "diagnosis",
    "disease":                      "diagnosis",
    "illness":                      "diagnosis",
    "chronic condition":            "diagnosis",
    "allergy":                      "allergies",
    "drug allergy":                 "allergies",
    "treatment":                    "treatment_history",
    "medical procedure":            "treatment_history",
}

# The actual list of labels we pass to GLiNER (de-duplicated, sorted)
GLINER_LABELS: list[str] = sorted(set(GLINER_LABEL_MAP.keys()))

# Min confidence to accept a GLiNER hit
_MIN_SCORE: float = 0.40


@lru_cache(maxsize=1)
def _load_model():
    """Load GLiNER model once per process. Returns None on failure."""
    try:
        from gliner import GLiNER  # type: ignore

        logger.info("[GLINER] Loading model: %s", _GLINER_MODEL_ID)
        model = GLiNER.from_pretrained(_GLINER_MODEL_ID)
        logger.info("[GLINER] Model loaded — labels: %d", len(GLINER_LABELS))
        return model
    except Exception as exc:
        logger.error("[GLINER] Model load failed: %s", exc)
        return None


class GLiNEREngine(BaseEngine):
    """
    Semantic NER engine using GLiNER.

    Best for: names, org names, medical entities, occupations, qualifications.
    Not ideal for: structured IDs with exact patterns (use RegexEngine instead).
    """

    name = "gliner"
    timeout = float(GLINER_TIMEOUT_SECONDS)


    def detect(
        self,
        text: str,
        labels: Optional[list[str]] = None,
        threshold: float = _DEFAULT_MIN_SCORE,
        **kwargs: Any,
    ) -> list[PIIMatch]:
        res = run_with_timeout(self._detect_internal, self.timeout, text, labels, threshold, **kwargs)
        if res is None:
            logger.warning("[GLINER] Timeout after %s seconds", self.timeout)
            return []
        return res

    def _detect_internal(
        self,
        text: str,
        labels: Optional[list[str]] = None,
        threshold: float = _DEFAULT_MIN_SCORE,
        **kwargs: Any,
    ) -> list[PIIMatch]:
        """
        Run GLiNER over *text* with per-type confidence thresholds.

        Per-type thresholds replace the old flat threshold — this eliminates
        junk like stopwords and sentence fragments being detected as names.
        """
        model = _load_model()
        if model is None:
            logger.warning("[GLINER] Skipped — model unavailable")
            return []

        active_labels = labels or GLINER_LABELS

        # GLiNER has a 384-token limit; chunk large texts to avoid truncation
        # Use the lowest per-type threshold as the model-level floor so we
        # don't discard borderline hits for types with higher limits.

        # Detect if text likely came from OCR (heuristic: high ratio of
        # non-alphanumeric noise, short lines, low avg word length)
        is_ocr_text = _is_likely_ocr(text)

        if is_ocr_text:
            model_threshold = min(_OCR_PER_TYPE_MIN_SCORE.values()) if _OCR_PER_TYPE_MIN_SCORE else (threshold - 0.20)
        else:
            model_threshold = min(_PER_TYPE_MIN_SCORE.values()) if _PER_TYPE_MIN_SCORE else threshold

        # Overlapping chunks to prevent entity splitting at boundaries.
        # Each element is (chunk_text, chunk_start_in_original_text).
        chunks = _chunk_text(text, max_chars=1200, overlap=200)
        all_matches: list[PIIMatch] = []

        for chunk, chunk_start in chunks:
            try:
                entities = model.predict_entities(
                    chunk, active_labels, threshold=model_threshold
                )
            except Exception as exc:
                logger.warning("[GLINER] Prediction error on chunk: %s", exc)
                continue

            for ent in entities:
                internal_id = GLINER_LABEL_MAP.get(ent["label"].lower())
                if not internal_id:
                    for label_key, iid in GLINER_LABEL_MAP.items():
                        if label_key in ent["label"].lower() or ent["label"].lower() in label_key:
                            internal_id = iid
                            break
                if not internal_id:
                    continue

                value = ent["text"].strip()
                if not value or len(value) < 2:
                    continue

                score = float(ent.get("score", model_threshold))

                # ── Per-type confidence gate (OCR-aware) ──────────────────────
                if is_ocr_text:
                    min_score = _OCR_PER_TYPE_MIN_SCORE.get(internal_id, 0.40)
                else:
                    min_score = _PER_TYPE_MIN_SCORE.get(internal_id, _DEFAULT_MIN_SCORE)

                if score < min_score:
                    continue

                # ── Name-specific guards ──────────────────────────────────────
                if internal_id == "name":
                    val_lower = value.lower()
                    if val_lower in _NAME_STOPWORDS:
                        continue
                    words = value.split()
                    # Reject single all-lowercase word (not a proper noun)
                    # But allow single capitalized words — valid Indian given names (e.g. "Pratik")
                    if len(words) == 1 and value == value.lower():
                        continue
                    # Reject sentences (>6 words)
                    if len(words) > 6:
                        continue
                    # Reject mostly-lowercase multi-word (not ID card names)
                    # Only for multi-word values; single capitalized words like "Pratik" are fine
                    if len(words) > 1:
                        lowercase_ratio = sum(1 for w in words if w and w[0].islower()) / len(words)
                        if lowercase_ratio > 0.6:
                            continue

                # ── Father name guards ────────────────────────────────────────
                elif internal_id == "father_name":
                    val_lower = value.lower()
                    if val_lower in _NAME_STOPWORDS:
                        continue
                    words = value.split()
                    # Reject single all-lowercase word
                    if len(words) == 1 and value == value.lower():
                        continue
                    # Father names on Indian ID cards typically 1-4 words
                    if len(words) > 5:
                        continue

                # ── Organization: reject very long strings ───────────────────
                elif internal_id == "organization":
                    if len(value.split()) > 8:
                        continue

                # ── Diagnosis: basic clinical keyword gate ────────────────────
                elif internal_id == "diagnosis":
                    _CLINICAL = re.compile(
                        r"(?i)\b(?:disease|disorder|syndrome|condition|infection|"
                        r"cancer|diabetes|hypertension|arthritis|sclerosis|lupus|"
                        r"psoriasis|colitis|anemia|neuropathy|hepatitis|asthma|"
                        r"copd|eczema|melanoma|tumor|autoimmune|chronic|acute|"
                        r"malignancy|diagnosed|diagnosis)\b"
                    )
                    if not _CLINICAL.search(value) and len(value.split()) > 3:
                        continue

                # Absolute span coordinates in original text
                start = ent.get("start", -1)
                end   = ent.get("end", -1)
                abs_start = (start + chunk_start) if start >= 0 else -1
                abs_end   = (end   + chunk_start) if end   >= 0 else -1
                ctx_start = max(0, start - 40)
                ctx_end   = min(len(chunk), (end if end >= 0 else start) + 40)
                context   = chunk[ctx_start:ctx_end].strip()

                all_matches.append(PIIMatch(
                    pii_type=internal_id,
                    value=value,
                    source="gliner",
                    confidence=score,
                    start=abs_start,
                    end=abs_end,
                    context=context,
                    metadata={"label": ent["label"]},
                ))

        logger.info("[GLINER] %d entities detected", len(all_matches))
        return all_matches


def _is_likely_ocr(text: str) -> bool:
    """Heuristic to detect if text likely came from OCR rather than digital extraction."""
    if not text or len(text) < 50:
        return False
    lines = text.split("\n")
    short_lines = sum(1 for l in lines if 0 < len(l.strip()) < 30)
    line_ratio = short_lines / max(len(lines), 1)
    # OCR text tends to have many short lines and lower avg word length
    words = text.split()
    avg_word_len = sum(len(w) for w in words) / max(len(words), 1)
    return line_ratio > 0.6 or avg_word_len < 4.0


def _chunk_text(text: str, max_chars: int = 1200, overlap: int = 200) -> list[tuple[str, int]]:
    """
    Split *text* into (chunk, start_pos) tuples of at most *max_chars* with
    *overlap* chars of context between chunks, breaking on sentence boundaries.
    Returns the start position of each chunk in the original text so callers
    can compute absolute entity spans correctly.
    """
    if len(text) <= max_chars:
        return [(text, 0)]

    chunks: list[tuple[str, int]] = []
    start = 0
    while start < len(text):
        end = start + max_chars
        if end >= len(text):
            chunks.append((text[start:], start))
            break
        # Try to break at a sentence boundary within the last 200 chars
        boundary = text.rfind(". ", start, end)
        if boundary == -1 or boundary <= start:
            boundary = text.rfind("\n", start, end)
        if boundary == -1 or boundary <= start:
            boundary = end
        else:
            boundary += 1  # include the period / newline
        chunks.append((text[start:boundary], start))
        # Step forward by (chunk_length - overlap) to create overlap
        step = max((boundary - start) - overlap, 1)
        start = start + step

    return chunks
