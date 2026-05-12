"""
services/text_normalizer.py
-----------------------------
Single-pass streaming text normalizer with persistent offset propagation.

Design principle
────────────────
Every transformation step runs character-by-character in ONE pass.
Offset mappings are updated IMMEDIATELY as each output character is emitted.
There is NO post-pass regex substitution after the alignment is built.

Two dense parallel arrays provide O(1) bidirectional span conversion:

  _norm_to_orig[norm_pos]  → orig_pos of the original char that produced it
  _orig_to_norm[orig_pos]  → norm_pos where this original char first appears
                             (-1 if the char was deleted / collapsed)

Why this matters
────────────────
The previous architecture applied re.sub() post-passes AFTER building the
alignment table, then tried to rebuild it.  That strategy fails for:
  - Indic / Arabic numerals (NFKC converts ৪ → 4 inline)
  - NFKC expansions that emit 0, 1, or N chars per input char
  - Whitespace runs collapsed by regex after the fact
  - Combining marks, ligatures, RTL text

With dense arrays populated during the single streaming pass none of those
cases can cause offset drift.

Transformations applied (in order, inline)
──────────────────────────────────────────
  1. Control/null bytes          → deleted   (no output, no mapping)
  2. Unicode substitution table  → mapped    (smart quotes, dashes, ligatures)
  3. Indic/Arabic numeral map    → 1:1       (Bengali ৪ → '4', Arabic ٤ → '4')
  4. NFKC normalization          → N:M       (fullwidth, circled, composed chars)
     └─ Inline whitespace dedup  → collapse  (3+ spaces → 2, 4+ newlines → 3)
"""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass, field


# ── Data container ─────────────────────────────────────────────────────────────

@dataclass
class NormalisedText:
    """
    Holds the normalized string and exact bidirectional offset maps.

    _norm_to_orig  — dense list; index = norm position, value = orig position
    _orig_to_norm  — dense list; index = orig position, value = norm position
                     (-1 means the original char was deleted/collapsed)
    """
    original:      str
    normalised:    str
    _norm_to_orig: list[int] = field(default_factory=list, repr=False)
    _orig_to_norm: list[int] = field(default_factory=list, repr=False)

    # ── Span conversion ───────────────────────────────────────────────────────

    def to_original_span(self, norm_start: int, norm_end: int) -> tuple[int, int]:
        """
        Convert a [norm_start, norm_end) span to the equivalent original span.

        Returns (-1, -1) if the mapping cannot be resolved.
        """
        n = len(self._norm_to_orig)
        if not n:
            return norm_start, norm_end   # no normalization was applied

        # Clamp to valid range
        ns = max(0, min(norm_start, n - 1))
        ne = max(0, min(norm_end - 1, n - 1))

        orig_start = self._norm_to_orig[ns]
        orig_last  = self._norm_to_orig[ne]

        # orig_end is exclusive — advance past the original char at orig_last
        orig_end = orig_last + 1

        # If multiple normalized chars share the same orig position (expansion),
        # the end is still orig_last + 1 which is correct.
        return orig_start, orig_end

    def to_norm_span(self, orig_start: int, orig_end: int) -> tuple[int, int]:
        """
        Convert an original [orig_start, orig_end) span to normalised space.
        """
        n = len(self._orig_to_norm)
        if not n:
            return orig_start, orig_end

        def _first_norm(op: int) -> int:
            for i in range(op, len(self._orig_to_norm)):
                v = self._orig_to_norm[i]
                if v >= 0:
                    return v
            return len(self._norm_to_orig)

        def _last_norm(op: int) -> int:
            for i in range(op - 1, -1, -1):
                v = self._orig_to_norm[i]
                if v >= 0:
                    return v + 1
            return 0

        ns = _first_norm(orig_start)
        ne = _last_norm(orig_end)
        return ns, max(ns, ne)


# ── Transformation tables (built at import time) ───────────────────────────────

_SUBSTITUTIONS: dict[str, str] = {
    # Smart quotes → ASCII
    "‘": "'",  "’": "'",  "“": '"',  "”": '"',
    # Dashes → hyphen
    "–": "-",  "—": "-",  "―": "-",
    # Ellipsis
    "…": "...",
    # OCR ligatures
    "ﬁ": "fi",  "ﬂ": "fl",  "ﬃ": "ffi",  "ﬄ": "ffl",
    "ﬀ": "ff",
    # Non-breaking / hair / thin spaces → regular space
    " ": " ",  " ": " ",  " ": " ",
    # Zero-width chars → deleted
    "​": "",  "‌": "",  "‍": "",  "﻿": "",
}

# Indic and Arabic digit codepoint ranges → ASCII digits
def _build_indic_map() -> dict[str, str]:
    m: dict[str, str] = {}
    ranges = [
        0x0966,  # Devanagari ०–९
        0x09E6,  # Bengali ০–৯
        0x0A66,  # Gurmukhi ੦–੯
        0x0AE6,  # Gujarati ૦–૯
        0x0B66,  # Odia ୦–୯
        0x0BE6,  # Tamil ௦–௯
        0x0C66,  # Telugu ౦–౯
        0x0CE6,  # Kannada ೦–೯
        0x0D66,  # Malayalam ൦–൯
        0x0660,  # Arabic-Indic ٠–٩
        0x06F0,  # Extended Arabic-Indic ۰–۹
        0x07C0,  # NKo ߀–߉
        0x0966,  # Already included (Devanagari)
        0x1040,  # Myanmar ၀–၉
        0x17E0,  # Khmer ០–៩
        0x1810,  # Mongolian ᠀–᠙
        0x1946,  # Limbu ᥆–᥏
        0xFF10,  # Fullwidth ０–９
    ]
    for base in ranges:
        for i in range(10):
            ch = chr(base + i)
            if ch not in m:
                m[ch] = str(i)
    return m

_INDIC_DIGITS: dict[str, str] = _build_indic_map()

# Control chars to delete (all C0 except \t=0x09, \n=0x0a, \r=0x0d)
_CTRL = frozenset(
    list(range(0x00, 0x09)) +
    [0x0b, 0x0c] +
    list(range(0x0e, 0x20)) +
    [0x7f]
)


# ── Single-pass streaming normalizer ──────────────────────────────────────────

def normalise(text: str) -> NormalisedText:
    """
    Normalize *text* in a single character-by-character pass.

    Returns a NormalisedText with exact norm↔orig offset arrays.
    No post-pass regex substitutions are applied.
    """
    if not text:
        return NormalisedText(
            original="", normalised="",
            _norm_to_orig=[], _orig_to_norm=[],
        )

    out:          list[str] = []       # normalized chars
    norm_to_orig: list[int] = []       # norm_pos → orig_pos
    orig_to_norm: list[int] = [-1] * len(text)   # orig_pos → norm_pos

    # Inline whitespace deduplication state
    _SPACE_CHARS = {' ', '\t'}
    consecutive_spaces  = 0   # current run of spaces/tabs in output
    consecutive_newlines = 0  # current run of newlines in output

    def _emit(orig_i: int, norm_ch: str) -> None:
        """Record one output character and update both offset arrays."""
        nonlocal consecutive_spaces, consecutive_newlines
        norm_pos = len(out)

        # Update orig→norm only on first emit for this orig_i
        if orig_to_norm[orig_i] == -1:
            orig_to_norm[orig_i] = norm_pos

        out.append(norm_ch)
        norm_to_orig.append(orig_i)

        # Update inline whitespace state
        if norm_ch in _SPACE_CHARS:
            consecutive_spaces   += 1
            consecutive_newlines  = 0
        elif norm_ch == '\n':
            consecutive_newlines += 1
            consecutive_spaces    = 0
        else:
            consecutive_spaces   = 0
            consecutive_newlines  = 0

    for orig_i, ch in enumerate(text):

        # ── 1. Delete control / null bytes ───────────────────────────────────
        if ord(ch) in _CTRL:
            # orig_to_norm[orig_i] stays -1 (deleted)
            continue

        # ── 2. Unicode substitution table ────────────────────────────────────
        sub = _SUBSTITUTIONS.get(ch)
        if sub is not None:
            for sc in sub:   # may be 0, 1, or multiple chars
                if sc in _SPACE_CHARS:
                    if consecutive_spaces < 2:
                        _emit(orig_i, sc)
                elif sc == '\n':
                    if consecutive_newlines < 3:
                        _emit(orig_i, sc)
                else:
                    _emit(orig_i, sc)
            # If sub is empty (zero-width), orig_to_norm stays -1
            continue

        # ── 3. Indic / Arabic digit normalization ─────────────────────────────
        digit = _INDIC_DIGITS.get(ch)
        if digit is not None:
            _emit(orig_i, digit)
            continue

        # ── 4. NFKC normalization ─────────────────────────────────────────────
        nfkc = unicodedata.normalize("NFKC", ch)
        # nfkc may be 0, 1, or N chars
        for nc in nfkc:
            if nc in _SPACE_CHARS:
                if consecutive_spaces < 2:
                    _emit(orig_i, nc)
            elif nc == '\n':
                if consecutive_newlines < 3:
                    _emit(orig_i, nc)
            else:
                _emit(orig_i, nc)
        # If nfkc is empty, orig_to_norm stays -1

    return NormalisedText(
        original=text,
        normalised="".join(out),
        _norm_to_orig=norm_to_orig,
        _orig_to_norm=orig_to_norm,
    )
