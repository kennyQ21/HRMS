"""
services/language_detector.py
-------------------------------
Script-aware language detection for engine routing.

Routing decision:
  Latin-script only    -> Regex + GLiNER
  Indic/Arabic only    -> Regex + Qwen NER
  Mixed                -> Regex + GLiNER + Qwen NER

Detection strategy:
  1. Token-level script classification (Unicode block analysis)
  2. Script distribution metrics
  3. langdetect fallback for ambiguous Latin-script languages

Output: LangResult with dominant_script, mixed_script_ratio,
        and routing flags for engine selection.
"""
from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)

# ── Script ranges for token-level classification ─────────────────────────────

SCRIPT_RANGES: list[tuple[int, int, str]] = [
    # Indic
    (0x0900, 0x097F, "devanagari"),   # Hindi, Marathi, Sanskrit
    (0x0980, 0x09FF, "bengali"),      # Bengali
    (0x0A00, 0x0A7F, "gurmukhi"),     # Punjabi
    (0x0A80, 0x0AFF, "gujarati"),     # Gujarati
    (0x0B00, 0x0B7F, "odia"),         # Odia
    (0x0B80, 0x0BFF, "tamil"),        # Tamil
    (0x0C00, 0x0C7F, "telugu"),       # Telugu
    (0x0C80, 0x0CFF, "kannada"),      # Kannada
    (0x0D00, 0x0D7F, "malayalam"),    # Malayalam
    # Middle East
    (0x0600, 0x06FF, "arabic"),       # Arabic / Urdu / Farsi
    (0x0590, 0x05FF, "hebrew"),       # Hebrew
    # East Asian
    (0x4E00, 0x9FFF, "cjk"),          # Chinese/Japanese/Korean
    (0x3040, 0x309F, "hiragana"),     # Japanese
    (0x30A0, 0x30FF, "katakana"),     # Japanese
    (0xAC00, 0xD7AF, "hangul"),       # Korean
    # Other
    (0x0400, 0x04FF, "cyrillic"),     # Russian/Ukrainian/etc.
    (0x0E00, 0x0E7F, "thai"),         # Thai
]

# Script groupings for routing
INDIC_SCRIPTS: frozenset[str] = frozenset({
    "devanagari", "bengali", "gurmukhi", "gujarati", "odia",
    "tamil", "telugu", "kannada", "malayalam",
})

ARABIC_SCRIPTS: frozenset[str] = frozenset({"arabic", "hebrew"})

CJK_SCRIPTS: frozenset[str] = frozenset({"cjk", "hiragana", "katakana", "hangul"})

LATIN_SCRIPT = "latin"

# ISO 639-1 mapping for backward compatibility
_SCRIPT_TO_LANG: dict[str, str] = {
    "devanagari": "hi", "bengali": "bn", "gurmukhi": "pa",
    "gujarati": "gu", "odia": "or", "tamil": "ta",
    "telugu": "te", "kannada": "kn", "malayalam": "ml",
    "arabic": "ar", "hebrew": "he", "cjk": "zh",
    "hiragana": "ja", "katakana": "ja", "hangul": "ko",
    "cyrillic": "ru", "thai": "th",
}


def _classify_char_script(cp: int) -> str:
    """Classify a single codepoint into a script family."""
    for lo, hi, script in SCRIPT_RANGES:
        if lo <= cp <= hi:
            return script
    return LATIN_SCRIPT


# ── Language groups for backward compatibility ────────────────────────────────

GLINER_LANGS: frozenset[str] = frozenset({"en", "en-gb", "en-us"})

QWEN_LANGS: frozenset[str] = frozenset({
    "hi", "bn", "ta", "te", "kn", "ml", "gu", "pa", "mr", "or", "si",
    "zh", "zh-cn", "zh-tw", "ja", "ko",
    "ar", "fa", "ur", "he",
    "th", "vi", "id", "ms", "tl",
    "fr", "de", "es", "pt", "it", "ru", "nl", "pl", "tr", "uk", "cs",
})


@dataclass
class LangResult:
    """Script-aware language detection result for engine routing."""
    dominant_script:    str               # "latin" | "devanagari" | "arabic" | etc.
    mixed_script_ratio: float             # 0.0–1.0 fraction of non-dominant script
    has_indic:          bool              # Any Indic script detected
    has_arabic:         bool              # Arabic/Hebrew script detected
    has_cjk:            bool              # CJK script detected
    is_multilingual:    bool              # Multiple scripts present
    script_distribution: dict[str, float] # script -> fraction of tokens
    # Backward-compatible fields
    primary_lang:       str               # ISO 639-1 code
    is_english:         bool
    has_foreign:        bool
    script_langs:       list[str]         # ISO codes for detected scripts
    confidence:         float


def detect(text: str) -> LangResult:
    """
    Detect language(s) and script distribution in *text*.

    Returns a LangResult with script-level routing information.
    """
    if not text or not text.strip():
        return LangResult(
            dominant_script=LATIN_SCRIPT, mixed_script_ratio=0.0,
            has_indic=False, has_arabic=False, has_cjk=False,
            is_multilingual=False, script_distribution={},
            primary_lang="en", is_english=True, has_foreign=False,
            script_langs=[], confidence=1.0,
        )

    # ── Token-level script classification ─────────────────────────────────────
    # Split into word tokens and classify each token by its first char
    tokens = re.findall(r'\S+', text)
    if not tokens:
        return LangResult(
            dominant_script=LATIN_SCRIPT, mixed_script_ratio=0.0,
            has_indic=False, has_arabic=False, has_cjk=False,
            is_multilingual=False, script_distribution={},
            primary_lang="en", is_english=True, has_foreign=False,
            script_langs=[], confidence=1.0,
        )

    script_counts: dict[str, int] = {}
    for token in tokens:
        # Classify by first non-punctuation character
        for ch in token:
            if ch.isalpha():
                script = _classify_char_script(ord(ch))
                script_counts[script] = script_counts.get(script, 0) + 1
                break

    total_tokens = max(sum(script_counts.values()), 1)
    script_distribution = {
        s: round(c / total_tokens, 3)
        for s, c in sorted(script_counts.items(), key=lambda x: -x[1])
    }

    # ── Determine dominant script ─────────────────────────────────────────────
    dominant_script = max(script_counts, key=script_counts.get) if script_counts else LATIN_SCRIPT
    dominant_ratio = script_counts.get(dominant_script, 0) / total_tokens

    # Mixed script ratio: fraction of tokens NOT in the dominant script
    mixed_script_ratio = round(1.0 - dominant_ratio, 3)

    # ── Script family flags ───────────────────────────────────────────────────
    detected_scripts = set(script_counts.keys())
    has_indic   = bool(detected_scripts & INDIC_SCRIPTS)
    has_arabic  = bool(detected_scripts & ARABIC_SCRIPTS)
    has_cjk     = bool(detected_scripts & CJK_SCRIPTS)
    is_multilingual = len(detected_scripts) > 1

    # ── Backward-compatible fields ────────────────────────────────────────────
    # Primary language from dominant script
    primary_lang = _SCRIPT_TO_LANG.get(dominant_script, "en")

    # langdetect fallback for Latin-script foreign languages
    if dominant_script == LATIN_SCRIPT and mixed_script_ratio < 0.15:
        try:
            from langdetect import detect_langs
            results = detect_langs(text[:2000])
            if results and results[0].prob > 0.80:
                primary_lang = results[0].lang
        except Exception:
            pass

    is_english = (
        dominant_script == LATIN_SCRIPT
        and primary_lang in ("en", "en-gb", "en-us")
        and mixed_script_ratio < 0.15
    )

    # Script langs for backward compat
    script_langs = [
        _SCRIPT_TO_LANG.get(s, s)
        for s in sorted(script_counts, key=script_counts.get, reverse=True)
        if script_counts[s] / total_tokens >= 0.02
    ]

    confidence = min(dominant_ratio * 1.5, 1.0)

    logger.debug(
        "[LANG] dominant=%s mixed=%.2f indic=%s arabic=%s cjk=%s multi=%s",
        dominant_script, mixed_script_ratio, has_indic, has_arabic, has_cjk, is_multilingual,
    )

    return LangResult(
        dominant_script=dominant_script,
        mixed_script_ratio=mixed_script_ratio,
        has_indic=has_indic,
        has_arabic=has_arabic,
        has_cjk=has_cjk,
        is_multilingual=is_multilingual,
        script_distribution=script_distribution,
        primary_lang=primary_lang,
        is_english=is_english,
        has_foreign=not is_english,
        script_langs=script_langs,
        confidence=round(confidence, 3),
    )
