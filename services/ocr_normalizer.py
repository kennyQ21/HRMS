"""
services/ocr_normalizer.py
---------------------------
Language-aware OCR text cleanup applied BEFORE detection engines.

Fixes applied:
  1. ZWJ / ZWNJ / soft hyphen / BOM removal (zero-width junk from PDF fonts)
  2. Private Use Area char removal (U+E000-U+F8FF, PDF font substitution artifacts)
  3. Arabic diacritic stripping (harakat marks that confuse tokenizers)
  4. Tab runs collapsed (3+ tabs to 1)
  5. Repeated punctuation collapsed (---- to -)
  6. NFC normalization for Indic grapheme composites

Does NOT change: Indic/Arabic/Latin script characters, alphanumerics, newlines.
"""
from __future__ import annotations

import re
import unicodedata

# Zero-width and bidirectional control chars — no semantic content
_ZW_CHARS = frozenset([
    "​",  # ZWSP
    "‌",  # ZWNJ
    "‍",  # ZWJ
    "‎",  # LRM
    "‏",  # RLM
    "‪",  # LRE
    "‫",  # RLE
    "‬",  # PDF
    "‭",  # LRO
    "‮",  # RLO
    "⁦",  # LRI
    "⁧",  # RLI
    "⁨",  # FSI
    "⁩",  # PDI
    "­",  # soft hyphen
    "﻿",  # BOM / ZWNBSP
    "￼",  # object replacement
])

# Arabic diacritics (harakat) — optional marks
_ARABIC_DIACRITICS = re.compile(
    "[ؐ-ًؚ-ٰٟۖ-ۜ۟-۪ۤۧۨ-ۭ]"
)

# Private Use Area: U+E000-U+F8FF (PDF font artifact chars)
_PUA = re.compile("[-]")

# 3+ repeated identical punctuation collapsed to 1
_REPEATED_PUNCT = re.compile(r"([^\w\s])\1{2,}")

# 3+ consecutive tabs collapsed to 1
_TAB_RUN = re.compile(r"\t{3,}")


def clean_ocr(text: str) -> str:
    """Apply language-aware OCR cleanup. Returns cleaned text for detection."""
    if not text:
        return text

    cleaned = "".join(ch for ch in text if ch not in _ZW_CHARS)
    cleaned = _PUA.sub("", cleaned)
    cleaned = _ARABIC_DIACRITICS.sub("", cleaned)
    cleaned = _TAB_RUN.sub("\t", cleaned)
    cleaned = _REPEATED_PUNCT.sub(r"\1", cleaned)
    cleaned = unicodedata.normalize("NFC", cleaned)

    return cleaned
