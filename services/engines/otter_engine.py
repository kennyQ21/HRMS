"""
services/engines/otter_engine.py
----------------------------------
Layer 3: Otter Structured Semantic Extractor.

Otter operates as a layout-aware, relational extraction engine. Unlike regex
(pattern matching) or GLiNER (sequence labelling), Otter understands
document *structure*:

  A. Table Understanding
     Reads header→value relationships in markdown/plain-text tables.
     E.g.  "Patient Name | Diagnosis" → links name to medical record.

  B. Form / Key-Value Understanding
     Detects "Label: Value" / "Label = Value" patterns across all PII types.
     Handles OCR spacing artefacts and multi-line values.

  C. Relationship Mapping
     Builds a simple entity graph: which entities appear in the same
     structural unit (row, form field, paragraph).

  D. Section-Aware Context
     Boosts confidence of entities appearing under known section headers
     (e.g., "Medical History:", "Patient Details:").

No external model required — Otter is implemented using spaCy (already
present as a Presidio dependency) + custom heuristics.
"""

from __future__ import annotations

import logging
import re
from typing import Any

from .base_engine import BaseEngine, PIIMatch

logger = logging.getLogger(__name__)

# ── Form field patterns (label → PII type) ───────────────────────────────────

_FORM_FIELD_MAP: dict[str, str] = {
    # Personal
    r"name":                    "name",
    r"full\s*name":             "name",
    r"first\s*name":            "name",
    r"last\s*name":             "name",
    r"patient\s*name":          "name",
    r"dob|date\s*of\s*birth":   "dob",
    r"gender|sex":              "gender",
    r"age":                     "age",
    r"marital\s*status":        "marital_status",
    r"nationality":             "nationality",
    # Contact
    r"email":                   "email",
    r"phone|mobile|contact":    "phone",
    # Address
    r"address|addr|residence":  "address",
    r"city|town":               "city",
    r"pin\s*code|zip|postal":   "pincode",
    # Government ID
    r"aadhaar|uid":             "aadhaar",
    r"pan\s*(?:no|number|card)?": "pan",
    r"passport\s*(?:no|number)?": "passport",
    r"voter\s*(?:id|card)?":    "voter_id",
    r"driving\s*licen[cs]e":    "driving_license",
    # Financial
    r"account\s*(?:no|number)?":"bank_account",
    r"upi\s*id":                "upi",
    r"ifsc":                    "ifsc",
    r"card\s*(?:no|number)?":   "credit_card",
    r"cvv|cvc":                 "cvv",
    # Medical
    r"diagnosis|condition":     "diagnosis",
    r"allerg(?:y|ies)":         "allergies",
    r"blood\s*group":           "blood_group",
    r"prescription|medication": "prescription",
    r"mrn|patient\s*id":        "mrn",
    r"treatment|procedure":     "treatment_history",
    r"vaccin|immuniz":          "immunization",
    # Insurance
    r"policy\s*(?:no|number)?": "insurance_policy",
    r"insurance\s*provider":    "insurance_provider",
    # Employment
    r"occupation|job\s*title|designation": "occupation",
    r"employee\s*id|emp\s*id":  "employee_id",
    r"company|employer":        "organization",
    # Educational
    r"qualification|degree|education": "educational_qualification",
    # Auth
    r"username|user\s*id|login":"user_id",
    r"password|passwd":         "password",
}

# Compile into list of (pattern, pii_type)
_COMPILED_FORM_FIELDS: list[tuple[re.Pattern, str]] = [
    (re.compile(rf"(?i)\b{pat}\b"), pii_type)
    for pat, pii_type in _FORM_FIELD_MAP.items()
]

# Key:Value separator pattern
_KV_SEP = re.compile(r"\s*[:=\|]\s*")

# Section headers that elevate context confidence
_MEDICAL_HEADERS = re.compile(
    r"(?i)\b(?:medical\s*history|patient\s*details?|diagnosis|clinical\s*notes?|"
    r"prescription|treatment|allerg(?:y|ies)|immunization|vital\s*signs?)\s*[:\-]?",
)
_PERSONAL_HEADERS = re.compile(
    r"(?i)\b(?:personal\s*(?:info(?:rmation)?|details?)|applicant|respondent|"
    r"employee|candidate)\s*[:\-]?",
)
_FINANCIAL_HEADERS = re.compile(
    r"(?i)\b(?:bank\s*details?|payment\s*info(?:rmation)?|financial\s*(?:info|data))\s*[:\-]?",
)

# Table row separator: markdown or whitespace-heavy
_TABLE_ROW = re.compile(r"(?:\|[^\n]*\||\t[^\n]+\t)")


class OtterEngine(BaseEngine):
    """
    Document-structure-aware PII extractor.

    Works on three structural patterns:
      1. Key: Value form fields (most enterprise documents)
      2. Markdown / TSV table rows
      3. Section-context boosted entities
    """

    name = "otter"

    # Max word count per entity type emitted by Otter
    _MAX_VALUE_WORDS: dict[str, int] = {
        "name": 5, "organization": 8, "city": 3, "address": 20,
        "dob": 4, "gender": 2, "age": 2, "diagnosis": 10,
        "prescription": 8, "allergies": 8,
    }
    _DEFAULT_MAX_WORDS = 15

    # Values that must never be emitted regardless of label
    _OTTER_STOPWORDS: frozenset[str] = frozenset({
        "yes", "no", "sure", "n/a", "na", "none", "unknown", "tbd",
        "patient", "client", "respondent", "individual", "person",
        "interviewer", "interviewee", "speaker",
    })

    def detect(self, text: str, **kwargs: Any) -> list[PIIMatch]:
        matches: list[PIIMatch] = []
        matches.extend(self._extract_form_fields(text))
        matches.extend(self._extract_table_rows(text))
        # NOTE: _extract_section_context removed — it promoted entire sentences
        # (e.g. pharmacy routing text) into diagnosis/name entities, causing
        # massive false positives on conversational / narrative documents.
        logger.info("[OTTER] %d structured entities extracted", len(matches))
        return matches

    # ── A. Form Field Extraction ──────────────────────────────────────────────

    def _extract_form_fields(self, text: str) -> list[PIIMatch]:
        """
        Detect "Label: Value" patterns across all MASTER_PIIS labels.
        Handles multi-token labels and OCR spacing noise.
        """
        matches: list[PIIMatch] = []
        # Split on newlines and double-newlines to get logical lines
        lines = re.split(r"\n{1,2}", text)

        for line in lines:
            stripped = line.strip()
            if not stripped:
                continue

            # Try to split on first separator
            parts = _KV_SEP.split(stripped, maxsplit=1)
            if len(parts) != 2:
                continue
            label_raw, value_raw = parts[0].strip(), parts[1].strip()
            if not value_raw or len(value_raw) < 1:
                continue

            # Match label against known form fields
            for pattern, pii_type in _COMPILED_FORM_FIELDS:
                if pattern.search(label_raw):
                    # ── Value guards ──────────────────────────────────────────
                    val_lower = value_raw.strip().lower()

                    # Reject stopwords
                    if val_lower in self._OTTER_STOPWORDS:
                        break

                    # Reject over-length values (sentences masquerading as entities)
                    word_count = len(value_raw.split())
                    max_words  = self._MAX_VALUE_WORDS.get(pii_type, self._DEFAULT_MAX_WORDS)
                    if word_count > max_words:
                        break

                    # Reject values that look like section headers or prose
                    if value_raw.isupper() and word_count > 4:
                        break

                    start = text.find(value_raw)
                    matches.append(PIIMatch(
                        pii_type=pii_type,
                        value=value_raw[:200],
                        source="otter",
                        confidence=0.80,
                        start=start,
                        end=start + len(value_raw) if start >= 0 else -1,
                        context=stripped,
                        metadata={"extraction": "form_field", "label": label_raw},
                    ))
                    break  # one label → one PII type per line

        return matches

    # ── B. Table Row Extraction ───────────────────────────────────────────────

    def _extract_table_rows(self, text: str) -> list[PIIMatch]:
        """
        Parse markdown-style tables.  Uses the header row to determine which
        column maps to which PII type, then extracts values from data rows.
        """
        matches: list[PIIMatch] = []
        # Find contiguous table blocks
        table_blocks = _TABLE_ROW.findall(text)
        if not table_blocks:
            return matches

        lines = text.splitlines()
        header_row: list[str] = []
        header_pii_types: list[str | None] = []

        for line in lines:
            cells = [c.strip() for c in line.split("|") if c.strip()]
            if not cells:
                continue

            if not header_row:
                # Check if any cell matches a known field
                candidates = []
                for cell in cells:
                    best = None
                    for pattern, pii_type in _COMPILED_FORM_FIELDS:
                        if pattern.search(cell):
                            best = pii_type
                            break
                    candidates.append(best)
                if any(c is not None for c in candidates):
                    header_row = cells
                    header_pii_types = candidates
                continue

            # Data row — align with header
            if set(c.replace("-", "").strip() for c in cells) <= {""}:
                # Separator row (---|---|---) — reset to allow new table
                header_row = []
                continue

            for col_idx, pii_type in enumerate(header_pii_types):
                if pii_type is None or col_idx >= len(cells):
                    continue
                value = cells[col_idx].strip()
                if not value:
                    continue
                start = text.find(value)
                matches.append(PIIMatch(
                    pii_type=pii_type,
                    value=value[:200],
                    source="otter",
                    confidence=0.75,
                    start=start,
                    end=start + len(value) if start >= 0 else -1,
                    context=line.strip(),
                    metadata={"extraction": "table_row", "column": header_row[col_idx] if col_idx < len(header_row) else ""},
                ))

        return matches

    # ── C. Section Context Boosting ───────────────────────────────────────────

    def _extract_section_context(self, text: str) -> list[PIIMatch]:
        """
        Detect entities that appear immediately after known section headers.
        The header provides structural context that boosts confidence.
        E.g. text following "Medical History:" is likely medical PII.
        """
        matches: list[PIIMatch] = []

        def _extract_after_header(pattern: re.Pattern, pii_hint: str) -> None:
            for m in pattern.finditer(text):
                # Take the next 300 chars after the header
                snippet_start = m.end()
                snippet = text[snippet_start: snippet_start + 300].strip()
                if not snippet:
                    continue
                # Take the first meaningful sentence
                first_sent = re.split(r"[.\n]", snippet)[0].strip()
                if len(first_sent) < 3:
                    continue
                start_abs = text.find(first_sent, snippet_start)
                matches.append(PIIMatch(
                    pii_type=pii_hint,
                    value=first_sent[:200],
                    source="otter",
                    confidence=0.65,
                    start=start_abs,
                    end=start_abs + len(first_sent) if start_abs >= 0 else -1,
                    context=text[max(0, m.start() - 10): snippet_start + 50].strip(),
                    metadata={"extraction": "section_context", "header": m.group().strip()},
                ))

        _extract_after_header(_MEDICAL_HEADERS, "diagnosis")
        _extract_after_header(_PERSONAL_HEADERS, "name")
        _extract_after_header(_FINANCIAL_HEADERS, "bank_account")

        return matches
