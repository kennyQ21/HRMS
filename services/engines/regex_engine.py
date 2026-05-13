"""
services/engines/regex_engine.py
----------------------------------
Layer 1: Deterministic Regex Engine.

Handles all MASTER_PIIS that have an explicit regex pattern.
Credit card numbers are Luhn-validated before being emitted.
Types that are better detected by NER/LLM (address, name, etc.) are
automatically excluded when the dispatcher passes `use_nlp=True`.
"""

from __future__ import annotations

import logging
import re
from typing import Optional

from constants import PII_TYPES
from services.entities import PIIMatch
from .base_engine import BaseEngine

logger = logging.getLogger(__name__)

# Compile all regex patterns exactly once at import time
_PATTERNS: dict[str, re.Pattern] = {
    p["id"]: re.compile(p["regex"])
    for p in PII_TYPES
    if p.get("regex")
}

# For these types regex is deliberately skipped when NLP is on — NER engines
# have higher recall for free-form text
_NLP_PREFERRED: set[str] = {"name", "address", "organization", "diagnosis", "allergies", "treatment_history"}
# Note: father_name has a regex handler, so NOT in NLP_PREFERRED

# Label-anchored name patterns — deterministic so they bypass the NLP filter.
# These fire when a name is explicitly preceded by a keyword label on an ID card.
_LABEL_NAME_PATTERNS: list[re.Pattern] = [
    # "Name: JOHN SMITH" / "Name - John Smith" (English, case-insensitive)
    re.compile(r"(?i)(?:full\s+)?name\s*[:\-]\s*([A-Z][A-Za-z\s\.]{1,40})(?:\n|\r|$|\s{2,})", re.MULTILINE),
    # Line before DOB on Aadhaar/PAN: all-caps 2-4 word line immediately above DOB line
    re.compile(r"(?m)^([A-Z][A-Z\s\.]{4,50})\r?\n(?:[A-Z\s\.]{1,50}\r?\n)?(?:DOB|Date\s+of\s+Birth|Year\s+of\s+Birth)", re.MULTILINE),
    # PAN card: name is the first ALL-CAPS 2-4 word line immediately after the DOB date
    # e.g.  "16/11/1974\nMOHANBHAI DEVJIBHAI PATEL\n..."
    re.compile(r"(?m)^(\d{1,2}[\/\-\.]\d{1,2}[\/\-\.]\d{2,4})\r?\n([A-Z]{2,}(?:\s+[A-Z]{2,}){1,3})\r?\n"),
    # Name after "Elector's Name" or "Voter Name" label (Voter ID cards)
    re.compile(r"(?i)(?:elector(?:'?s)?\s*name|voter\s*name)\s*[:\-]?\s*([A-Z][A-Za-z\s\.]{2,40})(?:\n|\r|$)", re.MULTILINE),
    # All-caps name that immediately follows a relation line (S/O, D/O, Father's Name)
    # e.g. "Father's Name:\nPATEL NARESH\nMOHANBHAI DEVJIBHAI PATEL ← cardholder"
    # Pattern: relation label then the SECOND all-caps line (the cardholder)
    re.compile(r"(?m)(?:(?:S\/O|D\/O|Father'?s?\s*(?:Name)?)[^\n]*\n)([A-Z]{2,}(?:\s+[A-Z]{2,}){1,3})(?=\s*\n)"),
]


def _luhn_valid(value: str) -> bool:
    digits = re.sub(r"\D", "", value)
    if not digits.isdigit() or len(digits) < 13:
        return False
    total = 0
    for i, ch in enumerate(reversed(digits)):
        d = int(ch)
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


class RegexEngine(BaseEngine):
    """
    Fast, deterministic PII detection using compiled regex patterns.

    Best for: structured IDs, card numbers, emails, phones, government IDs.
    Not ideal for: free-form narrative fields (name, address, diagnosis).
    """

    name = "regex"

    def detect(
        self,
        text: str,
        exclude_types: Optional[set[str]] = None,
        **kwargs,
    ) -> list[PIIMatch]:
        """
        Scan *text* with all compiled patterns.

        Args:
            text: Input text to scan.
            exclude_types: PII type IDs to skip (e.g. NLP-preferred types).

        Returns list of PIIMatch, one per distinct regex hit.
        """
        skip = (exclude_types or set()) | (
            _NLP_PREFERRED if kwargs.get("use_nlp") else set()
        )

        matches: list[PIIMatch] = []

        for pii_id, pattern in _PATTERNS.items():
            if pii_id in skip:
                continue

            for m in pattern.finditer(text):
                raw = m.group().strip()

                # --- type-specific post-processing / validation --------------
                if pii_id == "credit_card":
                    if not _luhn_valid(raw):
                        continue
                    raw = re.sub(r"\D", "", raw)

                elif pii_id == "phone":
                    raw = re.sub(r"\D", "", raw) or raw
                    # Reject reversed OCR phone numbers (+ at end, e.g. "9876543210+91")
                    if raw and not raw.startswith("91") and len(raw) < 10:
                        continue

                elif pii_id == "aadhaar":
                    raw = re.sub(r"\D", "", raw) or raw

                elif pii_id == "voter_id":
                    # Voter ID regex has two alternation groups:
                    # group(1) = EPIC-label-gated match, group(2) = bare 3-alpha+7-digit match
                    # Strip all internal whitespace/noise from OCR
                    g = None
                    if m.lastindex:
                        for gi in range(1, m.lastindex + 1):
                            if m.group(gi):
                                g = m.group(gi)
                                break
                    raw = re.sub(r"[\s.\-]+", "", g or raw).upper()

                elif pii_id == "father_name":
                    # father_name uses multiple capture groups; extract from the last non-None
                    if m.lastindex:
                        for gi in range(m.lastindex, 0, -1):
                            if m.group(gi):
                                raw = m.group(gi).strip().rstrip(".")
                                break
                    # Reject if too short or all-caps single-char noise
                    words = raw.split()
                    if len(words) == 1 and len(raw) <= 2:
                        continue

                elif pii_id == "dob":
                    # dob uses capture group(1) for the actual date value
                    if m.lastindex and m.lastindex >= 1 and m.group(1):
                        raw = m.group(1).strip()

                elif pii_id in {"pan", "driving_license", "passport",
                                 "ifsc", "ssn", "nhs_number"}:
                    # Strip internal whitespace/newlines from ID values.
                    # OCR on tab-separated layouts produces "ABCPS\n1234\nD"
                    # for a PAN card — normalise to "ABCPS1234D".
                    raw = re.sub(r"[\s\t\n\r]+", "", raw)

                elif pii_id in {"bank_account", "user_id", "password",
                                "insurance_policy", "mrn", "employee_id",
                                "allergies", "gender", "age",
                                "marital_status", "pincode"}:
                    # These patterns use a capture group; prefer group(1) if present
                    if m.lastindex and m.lastindex >= 1 and m.group(1):
                        raw = m.group(1).strip()

                elif pii_id == "email":
                    # Strip whitespace injected by PDF tab-separated layout
                    # e.g. "rajesh\n.\nsharma@gmail\n.\ncom" → "rajesh.sharma@gmail.com"
                    raw = re.sub(r"[ \t\n\r]+", "", raw)
                    # Reject if no @ remains after stripping
                    if "@" not in raw:
                        continue

                elif pii_id == "upi":
                    # Avoid matching plain email addresses as UPI IDs
                    if re.match(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}", raw):
                        continue

                # Build surrounding context snippet (±40 chars)
                ctx_start = max(0, m.start() - 40)
                ctx_end   = min(len(text), m.end() + 40)
                context   = text[ctx_start:ctx_end].strip()

                matches.append(PIIMatch(
                    pii_type=pii_id,
                    value=raw,
                    source="regex",
                    confidence=1.0,
                    start=m.start(),
                    end=m.end(),
                    context=context,
                ))

        # ── Label-anchored name extraction (always runs, not NLP-filtered) ────
        # Noise words that appear in ALL-CAPS on Indian ID cards but are NOT names
        _ID_CARD_NOISE = {
            "INDIA", "GOVERNMENT", "GOVT", "DEPARTMENT", "COMMISSION",
            "AADHAAR", "INCOME", "TAX", "ELECTION", "VOTER", "AUTHORITY",
            "IDENTIFICATION", "UNIQUE", "PERMANENT", "ACCOUNT", "NUMBER",
        }
        for pat in _LABEL_NAME_PATTERNS:
            for m in pat.finditer(text):
                # Extract name from last non-None capture group
                # (DOB-anchored pattern has name in group(2), others in group(1))
                value = None
                if m.lastindex:
                    for gi in range(m.lastindex, 0, -1):
                        if m.group(gi) and not re.match(r"^\d", m.group(gi)):
                            value = m.group(gi).strip().rstrip(".")
                            break
                if not value:
                    value = m.group().strip().rstrip(".")
                if not value or len(value) < 3:
                    continue
                # Skip obvious noise: single uppercase tokens that are labels/IDs
                words = value.split()
                if len(words) == 1 and (len(value) <= 2 or value.upper() in _ID_CARD_NOISE):
                    continue
                # Skip if all words are noise tokens
                if all(w.upper() in _ID_CARD_NOISE for w in words):
                    continue
                # Must have at least one word of 3+ chars (not a 2-char noise abbrev)
                if not any(len(w) >= 3 for w in words):
                    continue
                ctx_start = max(0, m.start() - 40)
                ctx_end   = min(len(text), m.end() + 40)
                # Use the group with the name value for span
                name_group = None
                if m.lastindex:
                    for gi in range(m.lastindex, 0, -1):
                        if m.group(gi) and not re.match(r"^\d", m.group(gi)):
                            name_group = gi
                            break
                span_start = m.start(name_group) if name_group else m.start()
                span_end   = m.end(name_group) if name_group else m.end()
                matches.append(PIIMatch(
                    pii_type="name",
                    value=value,
                    source="regex",
                    confidence=0.92,
                    start=span_start,
                    end=span_end,
                    context=text[ctx_start:ctx_end].strip(),
                ))

        logger.debug("[REGEX] %d raw matches across %d patterns", len(matches), len(_PATTERNS))
        return matches
