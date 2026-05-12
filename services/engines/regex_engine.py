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
from .base_engine import BaseEngine, PIIMatch

logger = logging.getLogger(__name__)

# Compile all regex patterns exactly once at import time
_PATTERNS: dict[str, re.Pattern] = {
    p["id"]: re.compile(p["regex"])
    for p in PII_TYPES
    if p.get("regex")
}

# For these types regex is deliberately skipped when NLP is on — NER engines
# have higher recall for free-form text
_NLP_PREFERRED: set[str] = {"name", "address", "organization", "city", "nationality"}


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

                elif pii_id in {"pan", "voter_id", "driving_license", "passport",
                                 "ifsc", "ssn", "nhs_number"}:
                    # Strip internal whitespace/newlines from ID values.
                    # OCR on tab-separated layouts produces "ABCPS\n1234\nD"
                    # for a PAN card — normalise to "ABCPS1234D".
                    raw = re.sub(r"[\s\t\n\r]+", "", raw)

                elif pii_id in {"bank_account", "user_id", "password",
                                "insurance_policy", "mrn", "employee_id",
                                "allergies", "dob", "gender", "age",
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

        logger.debug("[REGEX] %d raw matches across %d patterns", len(matches), len(_PATTERNS))
        return matches
