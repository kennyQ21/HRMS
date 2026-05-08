"""
services/engines/llm_engine.py
--------------------------------
Layer 4: Ollama / Qwen Semantic Reasoning Engine.

Qwen acts as a FIRST-CLASS detection engine — not a fallback.
It handles PII types that are fundamentally semantic in nature and cannot be
reliably extracted with regex or NER alone:

  • Medical diagnosis / treatment / allergies (narrative text)
  • Occupation / job title inferred from context
  • Educational qualifications inferred from descriptions
  • OCR-corrupted labels ("P4ssport No:" → passport)
  • Inferred / implicit PII ("completed Masters at IIT" → educational_qualification)
  • Insurance provider names in free text

Architecture:
  - Uses Ollama REST API (http://localhost:11434) — no extra Python package required
  - Model: qwen2.5:7b-instruct (confirmed present on this machine)
  - Text is chunked so each call stays within the model context window
  - Structured JSON extraction via prompt engineering + response parsing
  - Timeout + retry logic to keep latency predictable
  - Falls back gracefully if Ollama is unreachable
"""

from __future__ import annotations

import json
import logging
import re
import time
from typing import Any, Optional

import requests

from constants import LLM_PRIORITY_PII
from .base_engine import BaseEngine, PIIMatch

logger = logging.getLogger(__name__)

_OLLAMA_URL  = "http://localhost:11434/api/generate"
_MODEL       = "qwen2.5:7b-instruct"
_TIMEOUT_SEC = 60
_MAX_CHARS   = 2000   # max chars per LLM call (fits easily in 7B context)

# PII types the LLM handles best (semantic / inferred / narrative)
_LLM_TARGET_TYPES = LLM_PRIORITY_PII | {
    "name", "address", "organization", "occupation", "nationality",
    "insurance_provider", "educational_qualification",
}

_EXTRACTION_PROMPT = """\
You are a PII (Personally Identifiable Information) extraction expert.
Extract ALL PII entities from the text below.

For each entity, return a JSON array of objects with these keys:
  "type"       - one of: {types}
  "value"      - the exact text of the entity
  "confidence" - float 0.0-1.0 (how confident you are)
  "context"    - short surrounding phrase (max 20 words) explaining why it's PII

Only return the JSON array. No explanation, no markdown, no commentary.
If no PII is found, return [].

TEXT:
{text}

JSON:"""


def _build_prompt(text: str) -> str:
    types = ", ".join(sorted(_LLM_TARGET_TYPES))
    return _EXTRACTION_PROMPT.format(types=types, text=text)


def _call_ollama(prompt: str, timeout: int = _TIMEOUT_SEC) -> str:
    """Send prompt to Ollama and return the raw response string."""
    payload = {
        "model": _MODEL,
        "prompt": prompt,
        "stream": False,
        "options": {
            "temperature": 0.0,   # deterministic
            "top_p": 1.0,
            "num_predict": 1024,
        },
    }
    resp = requests.post(_OLLAMA_URL, json=payload, timeout=timeout)
    resp.raise_for_status()
    data = resp.json()
    return data.get("response", "")


def _parse_llm_response(raw: str) -> list[dict]:
    """
    Robustly parse LLM JSON output.

    The model sometimes wraps output in markdown ```json blocks or adds
    trailing text. We extract the first valid JSON array.
    """
    # Strip markdown fences
    raw = re.sub(r"```(?:json)?", "", raw).strip()

    # Find the first JSON array
    bracket_start = raw.find("[")
    bracket_end   = raw.rfind("]")
    if bracket_start == -1 or bracket_end == -1:
        return []

    json_str = raw[bracket_start: bracket_end + 1]
    try:
        entities = json.loads(json_str)
        if isinstance(entities, list):
            return entities
    except json.JSONDecodeError:
        # Try line-by-line recovery for partially truncated output
        lines = json_str.splitlines()
        fixed = []
        for line in lines:
            line = line.rstrip(",")
            try:
                obj = json.loads(line)
                if isinstance(obj, dict):
                    fixed.append(obj)
            except Exception:
                continue
        return fixed

    return []


class LLMEngine(BaseEngine):
    """
    Ollama/Qwen semantic reasoning engine.

    Best for: medical entities, occupations, inferred PII, OCR-corrupted labels.
    Not needed for: structured IDs (handled by RegexEngine).
    """

    name = "llm"

    def __init__(self, model: str = _MODEL, ollama_url: str = _OLLAMA_URL):
        self.model = model
        self.ollama_url = ollama_url

    def _is_available(self) -> bool:
        """Check if Ollama is reachable."""
        try:
            requests.get(self.ollama_url.replace("/api/generate", "/api/tags"), timeout=2)
            return True
        except Exception:
            return False

    def detect(
        self,
        text: str,
        target_types: Optional[set[str]] = None,
        **kwargs: Any,
    ) -> list[PIIMatch]:
        """
        Run Qwen over *text* to extract semantic PII.

        Args:
            text:         Input text (post-normalisation).
            target_types: Restrict to a subset of LLM-suited PII types.
        """
        if not self._is_available():
            logger.warning("[LLM] Ollama unavailable — skipping semantic pass")
            return []

        chunks = _chunk_text(text, _MAX_CHARS)
        all_matches: list[PIIMatch] = []
        offset = 0

        for chunk in chunks:
            chunk_stripped = chunk.strip()
            if not chunk_stripped:
                offset += len(chunk)
                continue

            prompt = _build_prompt(chunk_stripped)
            try:
                t0  = time.perf_counter()
                raw = _call_ollama(prompt)
                elapsed = (time.perf_counter() - t0) * 1000
                logger.info("[LLM] Ollama call: %.0f ms, chunk %d chars", elapsed, len(chunk_stripped))
            except requests.Timeout:
                logger.warning("[LLM] Ollama timed out for chunk of %d chars", len(chunk_stripped))
                offset += len(chunk)
                continue
            except Exception as exc:
                logger.error("[LLM] Ollama call failed: %s", exc)
                offset += len(chunk)
                continue

            entities = _parse_llm_response(raw)
            logger.debug("[LLM] raw entities from chunk: %s", entities)

            for ent in entities:
                if not isinstance(ent, dict):
                    continue
                pii_type   = str(ent.get("type", "")).strip().lower()
                value      = str(ent.get("value", "")).strip()
                confidence = float(ent.get("confidence", 0.7))
                context    = str(ent.get("context", "")).strip()

                if not pii_type or not value:
                    continue
                # Only keep types in MASTER_PIIS
                from constants import PII_TYPE_MAP
                if pii_type not in PII_TYPE_MAP:
                    # Fuzzy: e.g. LLM says "medical_condition" → "diagnosis"
                    pii_type = _fuzzy_type_match(pii_type)
                    if not pii_type:
                        continue

                if target_types and pii_type not in target_types:
                    continue

                # Try to find the value's position in the chunk
                pos = chunk_stripped.find(value)
                abs_start = (pos + offset) if pos >= 0 else -1
                abs_end   = (abs_start + len(value)) if abs_start >= 0 else -1

                all_matches.append(PIIMatch(
                    pii_type=pii_type,
                    value=value[:300],
                    source="llm",
                    confidence=min(max(confidence, 0.0), 1.0),
                    start=abs_start,
                    end=abs_end,
                    context=context,
                    metadata={"model": self.model},
                ))

            offset += len(chunk)

        logger.info("[LLM] %d semantic entities detected", len(all_matches))
        return all_matches


# ── Fuzzy type resolver ────────────────────────────────────────────────────────

_TYPE_ALIASES: dict[str, str] = {
    "medical condition":            "diagnosis",
    "medical_condition":            "diagnosis",
    "disease":                      "diagnosis",
    "illness":                      "diagnosis",
    "health condition":             "diagnosis",
    "allergy":                      "allergies",
    "drug allergy":                 "allergies",
    "job":                          "occupation",
    "job title":                    "occupation",
    "profession":                   "occupation",
    "designation":                  "occupation",
    "role":                         "occupation",
    "degree":                       "educational_qualification",
    "qualification":                "educational_qualification",
    "passport number":              "passport",
    "insurance number":             "insurance_policy",
    "policy number":                "insurance_policy",
    "blood type":                   "blood_group",
    "medication":                   "prescription",
    "drug":                         "prescription",
    "treatment":                    "treatment_history",
    "procedure":                    "treatment_history",
    "vaccination":                  "immunization",
    "vaccine":                      "immunization",
    "company":                      "organization",
    "employer":                     "organization",
    "bank account number":          "bank_account",
    "account number":               "bank_account",
    "username":                     "user_id",
    "login id":                     "user_id",
    "social security number":       "ssn",
    "license":                      "driving_license",
    "driving license":              "driving_license",
}


def _fuzzy_type_match(llm_type: str) -> str | None:
    """Map an unexpected LLM type string to a known MASTER_PIIS id."""
    from constants import PII_TYPE_MAP

    normalized = llm_type.lower().replace("-", "_")

    # Direct match
    if normalized in PII_TYPE_MAP:
        return normalized
    # Alias table
    if normalized in _TYPE_ALIASES:
        return _TYPE_ALIASES[normalized]
    # Substring match against known ids
    for pid in PII_TYPE_MAP:
        if pid in normalized or normalized in pid:
            return pid
    return None


def _chunk_text(text: str, max_chars: int) -> list[str]:
    if len(text) <= max_chars:
        return [text]
    chunks: list[str] = []
    start = 0
    while start < len(text):
        end = start + max_chars
        if end >= len(text):
            chunks.append(text[start:])
            break
        boundary = text.rfind(". ", start, end)
        if boundary == -1 or boundary <= start:
            boundary = text.rfind("\n", start, end)
        if boundary == -1 or boundary <= start:
            boundary = end
        else:
            boundary += 1
        chunks.append(text[start:boundary])
        start = boundary
    return chunks
