"""
services/language_detector.py
-------------------------------
Fast language and script detection used to route text to the right engine.

Routing decision:
  English only        → Regex + GLiNER
  Indic/Foreign only  → Regex + Qwen 0.5B
  Mixed               → Regex + GLiNER + Qwen 0.5B

Detection strategy (two-pass):
  1. Unicode block analysis (instant, script-level, handles noisy OCR well)
  2. langdetect fallback (for ambiguous Latin-script foreign languages)
"""
from __future__ import annotations

import re
import logging
from dataclasses import dataclass

logger = logging.getLogger(__name__)

# ── Language groups ───────────────────────────────────────────────────────────

# Languages GLiNER handles well (Latin-script, English-dominant training)
GLINER_LANGS: frozenset[str] = frozenset({
    "en", "en-gb", "en-us",
})

# Languages routed to Qwen 0.5B for semantic extraction
QWEN_LANGS: frozenset[str] = frozenset({
    # Indic
    "hi", "bn", "ta", "te", "kn", "ml", "gu", "pa", "mr", "or", "si",
    # East Asian
    "zh", "zh-cn", "zh-tw", "ja", "ko",
    # Middle East / South Asia
    "ar", "fa", "ur", "he",
    # Southeast Asian
    "th", "vi", "id", "ms", "tl",
    # European (non-English)
    "fr", "de", "es", "pt", "it", "ru", "nl", "pl", "tr", "uk", "cs",
    "ro", "hu", "sv", "da", "fi", "no",
    # African
    "sw", "am", "yo", "ha",
})

# Unicode block ranges for non-Latin scripts (fast detection without langdetect)
_SCRIPT_BLOCKS: list[tuple[int, int, str]] = [
    (0x0900, 0x097F, "hi"),   # Devanagari (Hindi, Marathi, Sanskrit)
    (0x0980, 0x09FF, "bn"),   # Bengali
    (0x0A00, 0x0A7F, "pa"),   # Gurmukhi (Punjabi)
    (0x0A80, 0x0AFF, "gu"),   # Gujarati
    (0x0B00, 0x0B7F, "or"),   # Odia
    (0x0B80, 0x0BFF, "ta"),   # Tamil
    (0x0C00, 0x0C7F, "te"),   # Telugu
    (0x0C80, 0x0CFF, "kn"),   # Kannada
    (0x0D00, 0x0D7F, "ml"),   # Malayalam
    (0x0600, 0x06FF, "ar"),   # Arabic (also Urdu/Farsi)
    (0x0590, 0x05FF, "he"),   # Hebrew
    (0x0E00, 0x0E7F, "th"),   # Thai
    (0x4E00, 0x9FFF, "zh"),   # CJK Unified Ideographs (Chinese/Japanese/Korean)
    (0x3040, 0x309F, "ja"),   # Hiragana
    (0x30A0, 0x30FF, "ja"),   # Katakana
    (0xAC00, 0xD7AF, "ko"),   # Hangul (Korean)
    (0x0400, 0x04FF, "ru"),   # Cyrillic (Russian/Ukrainian/etc.)
    (0x0530, 0x058F, "hy"),   # Armenian
    (0x10A0, 0x10FF, "ka"),   # Georgian
]

# Minimum fraction of non-ASCII chars to declare a text "foreign".
# Raised from 0.05 to 0.12 — OCR on English docs (Aadhaar, PAN, driving
# licences) often produces 5–10% noise chars that look like foreign script.
# At 0.12 we only trigger Qwen when genuinely multilingual content is present.
_FOREIGN_THRESHOLD = 0.12


@dataclass
class LangResult:
    primary_lang: str        # ISO 639-1 code of dominant language
    is_english: bool         # True if text is predominantly English
    has_foreign: bool        # True if any significant non-English content
    has_indic: bool          # True if Indic script detected
    script_langs: list[str]  # All scripts detected via Unicode blocks
    confidence: float        # Detection confidence


def detect(text: str) -> LangResult:
    """
    Detect language(s) present in *text*.

    Returns a LangResult with routing flags.
    """
    if not text or not text.strip():
        return LangResult("en", True, False, False, [], 1.0)

    # ── Pass 1: Unicode block scan (instant, OCR-noise-tolerant) ─────────────
    char_count  = len(text)
    block_hits: dict[str, int] = {}

    for ch in text:
        cp = ord(ch)
        for lo, hi, lang in _SCRIPT_BLOCKS:
            if lo <= cp <= hi:
                block_hits[lang] = block_hits.get(lang, 0) + 1
                break

    total_foreign_chars = sum(block_hits.values())
    foreign_ratio = total_foreign_chars / max(char_count, 1)

    script_langs = [
        lang for lang, cnt in sorted(block_hits.items(), key=lambda x: -x[1])
        if cnt / max(char_count, 1) >= 0.02    # at least 2% of chars
    ]

    has_indic = any(lang in {"hi","bn","ta","te","kn","ml","gu","pa","mr","or"} for lang in script_langs)
    has_foreign_script = foreign_ratio >= _FOREIGN_THRESHOLD

    # ── Pass 2: langdetect for Latin-script foreign languages ─────────────────
    detected_lang = "en"
    langdetect_conf = 0.0
    if not has_foreign_script:
        try:
            from langdetect import detect_langs
            results = detect_langs(text[:2000])   # limit for speed
            if results:
                top = results[0]
                detected_lang    = top.lang
                langdetect_conf  = top.prob
        except Exception:
            pass

    # ── Determine primary language ────────────────────────────────────────────
    if script_langs:
        primary_lang = script_langs[0]
    elif detected_lang != "en" and langdetect_conf > 0.80:
        primary_lang = detected_lang
    else:
        primary_lang = "en"

    is_english = (
        primary_lang == "en"
        and not has_foreign_script
        and detected_lang in ("en", "unknown")
    )

    confidence = langdetect_conf if not has_foreign_script else min(foreign_ratio * 2, 1.0)

    logger.debug(
        "[LANG] primary=%s english=%s foreign_ratio=%.2f scripts=%s",
        primary_lang, is_english, foreign_ratio, script_langs,
    )

    return LangResult(
        primary_lang=primary_lang,
        is_english=is_english,
        has_foreign=not is_english,
        has_indic=has_indic,
        script_langs=script_langs,
        confidence=round(confidence, 3),
    )
