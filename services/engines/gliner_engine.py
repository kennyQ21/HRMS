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
from functools import lru_cache
from typing import Any, Optional

from .base_engine import BaseEngine, PIIMatch

logger = logging.getLogger(__name__)

# Default model — balanced quality vs memory (~370 MB on disk)
# Swap for "urchade/gliner_large-v2.1" for higher accuracy at the cost of speed
_GLINER_MODEL_ID = "urchade/gliner_mediumv2.1"

# Maps GLiNER natural-language labels → MASTER_PIIS internal ids
GLINER_LABEL_MAP: dict[str, str] = {
    # Personal
    "person":                       "name",
    "person name":                  "name",
    "full name":                    "name",
    "individual":                   "name",
    # Organisations
    "organization":                 "organization",
    "company":                      "organization",
    "institution":                  "organization",
    "hospital":                     "organization",
    "bank":                         "organization",
    # Geo / location
    "location":                     "address",
    "address":                      "address",
    "street address":               "address",
    "city":                         "city",
    "town":                         "city",
    # Occupation
    "occupation":                   "occupation",
    "job title":                    "occupation",
    "profession":                   "occupation",
    "designation":                  "occupation",
    # Nationality
    "nationality":                  "nationality",
    "citizenship":                  "nationality",
    "country of origin":            "nationality",
    # Medical
    "medical condition":            "diagnosis",
    "diagnosis":                    "diagnosis",
    "disease":                      "diagnosis",
    "illness":                      "diagnosis",
    "chronic condition":            "diagnosis",
    "allergy":                      "allergies",
    "drug allergy":                 "allergies",
    "medication":                   "prescription",
    "drug":                         "prescription",
    "prescription":                 "prescription",
    "treatment":                    "treatment_history",
    "medical procedure":            "treatment_history",
    "vaccination":                  "immunization",
    "vaccine":                      "immunization",
    # Insurance
    "insurance provider":           "insurance_provider",
    "insurance company":            "insurance_provider",
    # Educational
    "educational qualification":    "educational_qualification",
    "degree":                       "educational_qualification",
    "diploma":                      "educational_qualification",
    "certification":                "educational_qualification",
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

    def detect(
        self,
        text: str,
        labels: Optional[list[str]] = None,
        threshold: float = _MIN_SCORE,
        **kwargs: Any,
    ) -> list[PIIMatch]:
        """
        Run GLiNER over *text* with the configured label set.

        Args:
            text:      Input text (post-normalisation).
            labels:    Override default GLINER_LABELS if needed.
            threshold: Minimum confidence score to keep a hit.
        """
        model = _load_model()
        if model is None:
            logger.warning("[GLINER] Skipped — model unavailable")
            return []

        active_labels = labels or GLINER_LABELS

        # GLiNER has a 384-token limit; chunk large texts to avoid truncation
        chunks = _chunk_text(text, max_chars=1500)
        all_matches: list[PIIMatch] = []
        offset = 0

        for chunk in chunks:
            try:
                entities = model.predict_entities(
                    chunk, active_labels, threshold=threshold
                )
            except Exception as exc:
                logger.warning("[GLINER] Prediction error on chunk: %s", exc)
                offset += len(chunk)
                continue

            for ent in entities:
                internal_id = GLINER_LABEL_MAP.get(ent["label"].lower())
                if not internal_id:
                    offset_label = ent["label"].lower()
                    # Fuzzy fallback: check if any label key is a substring
                    for label_key, iid in GLINER_LABEL_MAP.items():
                        if label_key in offset_label or offset_label in label_key:
                            internal_id = iid
                            break
                if not internal_id:
                    continue

                value = ent["text"].strip()
                if not value or len(value) < 2:
                    continue

                start = ent.get("start", -1)
                end   = ent.get("end", -1)
                abs_start = (start + offset) if start >= 0 else -1
                abs_end   = (end + offset) if end >= 0 else -1

                ctx_start = max(0, start - 40)
                ctx_end   = min(len(chunk), (end if end >= 0 else start) + 40)
                context   = chunk[ctx_start:ctx_end].strip()

                all_matches.append(PIIMatch(
                    pii_type=internal_id,
                    value=value,
                    source="gliner",
                    confidence=float(ent.get("score", threshold)),
                    start=abs_start,
                    end=abs_end,
                    context=context,
                    metadata={"label": ent["label"]},
                ))

            offset += len(chunk)

        logger.info("[GLINER] %d entities detected", len(all_matches))
        return all_matches


def _chunk_text(text: str, max_chars: int = 1500) -> list[str]:
    """
    Split *text* into chunks of at most *max_chars*, breaking on sentence
    boundaries where possible to preserve context.
    """
    if len(text) <= max_chars:
        return [text]

    chunks: list[str] = []
    start = 0
    while start < len(text):
        end = start + max_chars
        if end >= len(text):
            chunks.append(text[start:])
            break
        # Try to break at a sentence boundary within the last 200 chars
        boundary = text.rfind(". ", start, end)
        if boundary == -1 or boundary <= start:
            boundary = text.rfind("\n", start, end)
        if boundary == -1 or boundary <= start:
            boundary = end
        else:
            boundary += 1  # include the period / newline
        chunks.append(text[start:boundary])
        start = boundary

    return chunks
