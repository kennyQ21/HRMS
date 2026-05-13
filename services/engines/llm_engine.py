"""
services/engines/llm_engine.py
--------------------------------
Qwen 0.5B multilingual PII engine (via Ollama).

When it runs:
  - Non-English / Indic / foreign script text
  - Medical documents (any language)
  - Mixed-language documents

When it does NOT run:
  - Pure English text  →  GLiNER handles it
  - Structured IDs     →  Regex handles it
  - Short text (<20 words)

Qwen 0.5B constraints (important for accuracy):
  - Constrained extraction: only a targeted list of entity types per call
  - Small chunks: 512 chars max (reduces hallucination on small model)
  - Temperature 0.0: fully deterministic
  - Minimum confidence 0.70 accepted
  - No unrestricted "extract everything" prompts
"""

from __future__ import annotations

import json
import logging
import re
import time
from typing import Any, Optional

import requests

from constants import PII_TYPE_MAP
from services.entities import PIIMatch
from .base_engine import BaseEngine

logger = logging.getLogger(__name__)

_OLLAMA_URL  = "http://localhost:11434/api/generate"
_MODEL       = "qwen2.5:0.5b"
_TIMEOUT_SEC = 60
_MAX_CHARS   = 512     # small chunks → less hallucination on 0.5B

# Entity types Qwen targets: semantic + multilingual
# Do NOT include structured IDs (regex handles them far better)
_QWEN_ENTITY_TYPES: list[str] = [
    "name",
    "address",
    "organization",
    "city",
    "nationality",
    "occupation",
    "diagnosis",
    "allergies",
    "prescription",
    "treatment_history",
    "insurance_provider",
    "medication",
    "abha_number",
    "weight",
    "height",
    "annual_income",
    "credit_score",
    "contact",
    "lab_test_results",
]

# Constrained prompt — targeted list, strict JSON, no free-text extraction
_PROMPT = """\
Extract ONLY these entity types from the text:
{types}

Rules:
- Return a JSON array only, no explanation.
- Each item: {{"type": "<type>", "value": "<exact text>", "confidence": <0.0-1.0>}}
- Preserve original script (do not transliterate).
- Minimum confidence: 0.70. Skip uncertain entities.
- If nothing found, return [].

TEXT:
{text}

JSON:"""


def _build_prompt(text: str) -> str:
    types = ", ".join(_QWEN_ENTITY_TYPES)
    return _PROMPT.format(types=types, text=text.strip())


def _call_ollama(prompt: str, timeout: int = _TIMEOUT_SEC) -> str:
    payload = {
        "model": _MODEL,
        "prompt": prompt,
        "stream": False,
        "options": {
            "temperature": 0.0,
            "top_p": 1.0,
            "num_predict": 512,
            "repeat_penalty": 1.1,
        },
    }
    resp = requests.post(_OLLAMA_URL, json=payload, timeout=timeout)
    resp.raise_for_status()
    return resp.json().get("response", "")


def _sanitize_json(raw: str) -> str:
    # Fix invalid JSON escape sequences from small LLMs.
    # json.loads rejects backslash-p, backslash-a, backslash-s etc.
    # Valid escapes are: " \ / b f n r t and u followed by 4 hex digits.
    valid_escapes = frozenset('"\\' + '/bfnrtu')
    def _fix(m: re.Match) -> str:
        ch = m.group(1)
        return m.group(0) if ch in valid_escapes else ch
    return re.sub(r'\\(.)', _fix, raw)


def _parse_response(raw: str) -> list[dict]:
    """Robustly extract JSON array from LLM output."""
    raw = re.sub(r"```(?:json)?", "", raw).strip()
    start = raw.find("[")
    end   = raw.rfind("]")
    if start == -1 or end == -1:
        return []

    json_str = _sanitize_json(raw[start:end+1])

    try:
        result = json.loads(json_str)
        return result if isinstance(result, list) else []
    except json.JSONDecodeError:
        pass

    # Recovery: parse individual objects
    objects = re.findall(r"\{[^{}]+\}", json_str, re.DOTALL)
    recovered = []
    for obj_str in objects:
        try:
            obj = json.loads(_sanitize_json(obj_str))
            if isinstance(obj, dict) and "type" in obj and "value" in obj:
                recovered.append(obj)
        except Exception:
            continue
    return recovered


# ── Type normalizer ────────────────────────────────────────────────────────────

_ALIASES: dict[str, str] = {
    "person_name":        "name",
    "person":             "name",
    "full_name":          "name",
    "medical_condition":  "diagnosis",
    "disease":            "diagnosis",
    "illness":            "diagnosis",
    "condition":          "diagnosis",
    "allergy":            "allergies",
    "drug_allergy":       "allergies",
    "medication":         "medication",
    "drug":               "medication",
    "medicine":           "medication",
    "treatment":          "treatment_history",
    "procedure":          "treatment_history",
    "company":            "organization",
    "employer":           "organization",
    "job":                "occupation",
    "job_title":          "occupation",
    "profession":         "occupation",
    "role":               "occupation",
    "city":               "city",
    "location":           "city",
    "town":               "city",
    "insurance":          "insurance_provider",
}


def _normalize_type(raw_type: str) -> str | None:
    t = raw_type.strip().lower().replace("-", "_").replace(" ", "_")
    if t in PII_TYPE_MAP:
        return t
    if t in _ALIASES:
        return _ALIASES[t]
    # Substring match
    for pid in PII_TYPE_MAP:
        if pid in t or t in pid:
            return pid
    return None


# ── Engine ────────────────────────────────────────────────────────────────────

class LLMEngine(BaseEngine):
    """
    Qwen 0.5B multilingual PII engine.
    Only activates for non-English or medical documents.
    Skips gracefully when Ollama is not running.
    """

    name = "llm"

    def __init__(self, model: str = _MODEL, ollama_url: str = _OLLAMA_URL):
        self.model      = model
        self.ollama_url = ollama_url

    def _is_available(self) -> bool:
        try:
            r = requests.get(
                self.ollama_url.replace("/api/generate", "/api/tags"),
                timeout=2,
            )
            return r.status_code == 200
        except Exception:
            return False

    def detect(
        self,
        text: str,
        lang=None,    # LangResult from language_detector (optional)
        **kwargs: Any,
    ) -> list[PIIMatch]:

        if not self._is_available():
            logger.warning("[LLM] Ollama not running — skipping multilingual pass")
            return []

        chunks      = _chunk_text(text, _MAX_CHARS)
        all_matches: list[PIIMatch] = []
        offset      = 0

        for chunk in chunks:
            chunk = chunk.strip()
            if not chunk or len(chunk.split()) < 5:
                offset += len(chunk)
                continue

            prompt = _build_prompt(chunk)
            try:
                t0  = time.perf_counter()
                raw = _call_ollama(prompt, timeout=_TIMEOUT_SEC)
                elapsed = (time.perf_counter() - t0) * 1000
                logger.info("[LLM] %.0f ms — %d chars", elapsed, len(chunk))
            except requests.Timeout:
                logger.warning("[LLM] Timeout on %d-char chunk", len(chunk))
                offset += len(chunk)
                continue
            except Exception as exc:
                logger.error("[LLM] Call failed: %s", exc)
                offset += len(chunk)
                continue

            for ent in _parse_response(raw):
                if not isinstance(ent, dict):
                    continue

                raw_type   = str(ent.get("type", "")).strip()
                value      = str(ent.get("value", "")).strip()
                confidence = float(ent.get("confidence", 0.7))

                if not raw_type or not value or len(value) < 2:
                    continue
                if confidence < 0.70:
                    continue

                pii_type = _normalize_type(raw_type)
                if not pii_type:
                    continue

                pos       = _fuzzy_find(chunk, value)
                abs_start = (pos + offset) if pos >= 0 else -1
                abs_end   = (abs_start + len(value)) if abs_start >= 0 else -1

                language_tag = getattr(lang, "primary_lang", "unknown") if lang else "unknown"

                all_matches.append(PIIMatch(
                    pii_type=pii_type,
                    value=value[:300],
                    source="llm",
                    confidence=min(max(confidence, 0.0), 1.0),
                    start=abs_start,
                    end=abs_end,
                    context=chunk[:80],
                    metadata={"model": self.model, "language": language_tag},
                ))

            offset += len(chunk)

        logger.info("[LLM] %d multilingual entities detected", len(all_matches))
        return all_matches


def _chunk_text(text: str, max_chars: int, overlap: int = 150) -> list[str]:
    """Split text into chunks of ≤max_chars with overlap, breaking at sentence boundaries."""
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
        step = max((boundary - start) - overlap, 1)
        start = start + step
    return chunks


def _fuzzy_find(text: str, value: str) -> int:
    """
    Lightweight fuzzy matching fallback for LLM span recovery.
    Tries: exact → case-normalized → whitespace-normalized → punctuation-normalized.
    Returns index or -1.
    """
    # Exact match
    pos = text.find(value)
    if pos >= 0:
        return pos

    import re as _re

    # Case-normalized
    text_lower = text.lower()
    value_lower = value.lower()
    pos = text_lower.find(value_lower)
    if pos >= 0:
        return pos

    # Whitespace + punctuation normalized
    def _norm(s: str) -> str:
        # \p{P} (Unicode punctuation property) is not supported by Python's
        # re module — use an explicit ASCII punctuation class instead.
        return _re.sub(r'[\s!"#$%&\'()*+,\-./:;<=>?@\[\\\]^_`{|}~]+', " ", s).strip().lower()

    norm_text = _norm(text)
    norm_value = _norm(value)
    pos = norm_text.find(norm_value)
    if pos >= 0:
        # Map back to original position (approximate)
        # Count non-space chars up to pos in normalized text
        char_count = 0
        for i, ch in enumerate(text):
            if not ch.isspace() and ch not in ".,;:!?()-":
                char_count += 1
                if char_count >= pos:
                    return max(i - len(value) // 2, 0)
        return 0

    return -1
