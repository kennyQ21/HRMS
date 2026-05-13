"""
services/engines/qwen_ner_engine.py
-------------------------------------
Qwen 2.5 multilingual NER engine (via Ollama) — CONSTRAINED EXTRACTION ONLY.

When it runs:
  - Indic / Arabic / CJK script text (where GLiNER is weak)
  - Mixed-language documents with non-Latin content

When it does NOT run:
  - Pure Latin/English text -> GLiNER handles it
  - Structured IDs -> Regex handles them
  - Short text (<20 words)

CRITICAL SAFEGUARDS:
  - Constrained prompts: ONLY targeted entity types, strict JSON
  - NO "extract everything" prompts (causes hallucination)
  - ALL outputs pass span_grounding() in entity_resolution.py
  - Temperature 0.0: fully deterministic
  - Minimum confidence 0.75 accepted
  - Placeholder / hallucination rejection in post_processor
"""

from __future__ import annotations

import json
import logging
import re
import time
from typing import Any, Optional

import requests

from constants import PII_TYPE_MAP, QWEN_TIMEOUT_SECONDS
from services.entities import PIIMatch
from services.utils.timeout import run_with_timeout
from .base_engine import BaseEngine

logger = logging.getLogger(__name__)

_OLLAMA_URL  = "http://localhost:11434/api/generate"
_MODEL       = "qwen2.5:0.5b"
_TIMEOUT_SEC = QWEN_TIMEOUT_SECONDS
_MAX_CHARS   = 512

# ONLY high-value semantic types — same scope as GLiNER
# Do NOT add structured IDs (regex handles them far better)
_QWEN_NER_TYPES: list[str] = [
    "name",
    "father_name",
    "address",
    "organization",
    "diagnosis",
    "allergies",
    "treatment_history",
]

# Constrained prompt — targeted list, strict JSON, no free-text extraction
_PROMPT = """\
Extract ONLY these entity types from the text:
{name}, {father_name}, {address}, {organization}, {diagnosis}, {allergies}, {treatment_history}

Rules:
- Return a JSON array only, no explanation.
- Each item: {{"type": "<type>", "value": "<exact text from document>", "confidence": <0.75-1.0>}}
- Preserve original script (do not transliterate).
- Minimum confidence: 0.75. Skip uncertain entities.
- ONLY extract entities that are EXPLICITLY present in the text.
- Do NOT invent, guess, or infer entities.
- If nothing found, return []

TEXT:
{text}

JSON:"""


def _build_prompt(text: str) -> str:
    return _PROMPT.format(
        name="NAME", father_name="FATHER_NAME", address="ADDRESS",
        organization="ORGANIZATION",
        diagnosis="DIAGNOSIS", allergies="ALLERGIES",
        treatment_history="TREATMENT_HISTORY",
        text=text.strip(),
    )


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
    "name":               "name",
    "father_name":        "father_name",
    "father's_name":      "father_name",
    "guardian_name":      "father_name",
    "relation_name":      "father_name",
    "s/o":                "father_name",
    "d/o":                "father_name",
    "w/o":                "father_name",
    "address":            "address",
    "location":           "address",
    "street_address":     "address",
    "organization":       "organization",
    "company":            "organization",
    "institution":        "organization",
    "hospital":           "organization",
    "medical_condition":  "diagnosis",
    "disease":            "diagnosis",
    "illness":            "diagnosis",
    "condition":          "diagnosis",
    "diagnosis":          "diagnosis",
    "allergy":            "allergies",
    "drug_allergy":       "allergies",
    "allergies":          "allergies",
    "treatment":          "treatment_history",
    "medical_procedure":  "treatment_history",
    "treatment_history":  "treatment_history",
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


# ── Chunking ──────────────────────────────────────────────────────────────────

def _chunk_text(text: str, max_chars: int, overlap: int = 150) -> list[str]:
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
    """Lightweight fuzzy matching for span recovery."""
    pos = text.find(value)
    if pos >= 0:
        return pos

    text_lower = text.lower()
    value_lower = value.lower()
    pos = text_lower.find(value_lower)
    if pos >= 0:
        return pos

    return -1


# ── Engine ────────────────────────────────────────────────────────────────────

class QwenNEREngine(BaseEngine):
    """
    Qwen 2.5 multilingual NER engine — CONSTRAINED EXTRACTION ONLY.

    Only activates for Indic/Arabic/CJK text where GLiNER is weak.
    All outputs are grounded against source text in entity_resolution.py.
    Skips gracefully when Ollama is not running.
    """

    name = "qwen_ner"
    timeout = float(QWEN_TIMEOUT_SECONDS)

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
        labels: Optional[list[str]] = None,
        **kwargs: Any,
    ) -> list[PIIMatch]:
        res = run_with_timeout(self._detect_internal, self.timeout, text, labels, **kwargs)
        if res is None:
            logger.warning("[Qwen_NER] Timeout after %s seconds", self.timeout)
            return []
        return res

    def _detect_internal(
        self,
        text: str,
        lang=None,
        **kwargs: Any,
    ) -> list[PIIMatch]:

        if not self._is_available():
            logger.warning("[QWEN-NER] Ollama not running -- skipping multilingual NER pass")
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
                logger.info("[QWEN-NER] %.0f ms -- %d chars", elapsed, len(chunk))
            except requests.Timeout:
                logger.warning("[QWEN-NER] Timeout on %d-char chunk", len(chunk))
                offset += len(chunk)
                continue
            except Exception as exc:
                logger.error("[QWEN-NER] Call failed: %s", exc)
                offset += len(chunk)
                continue

            for ent in _parse_response(raw):
                if not isinstance(ent, dict):
                    continue

                raw_type   = str(ent.get("type", "")).strip()
                value      = str(ent.get("value", "")).strip()
                confidence = float(ent.get("confidence", 0.75))

                if not raw_type or not value or len(value) < 2:
                    continue
                if confidence < 0.75:
                    continue

                pii_type = _normalize_type(raw_type)
                if not pii_type:
                    continue

                # Only accept types in our constrained scope
                if pii_type not in {"name", "father_name", "address", "organization",
                                     "diagnosis", "allergies", "treatment_history"}:
                    continue

                pos       = _fuzzy_find(chunk, value)
                abs_start = (pos + offset) if pos >= 0 else -1
                abs_end   = (abs_start + len(value)) if abs_start >= 0 else -1

                language_tag = getattr(lang, "primary_lang", "unknown") if lang else "unknown"
                dominant_script = getattr(lang, "dominant_script", "unknown") if lang else "unknown"

                all_matches.append(PIIMatch(
                    pii_type=pii_type,
                    value=value[:300],
                    source="qwen_ner",
                    confidence=min(max(confidence, 0.0), 1.0),
                    start=abs_start,
                    end=abs_end,
                    context=chunk[:80],
                    metadata={
                        "model": self.model,
                        "language": language_tag,
                        "dominant_script": dominant_script,
                    },
                ))

            offset += len(chunk)

        logger.info("[QWEN-NER] %d multilingual entities detected", len(all_matches))
        return all_matches
