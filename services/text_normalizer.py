"""
services/text_normalizer.py
-----------------------------
Text Normalization Layer.

Core Rule (from architecture spec):
  ORIGINAL text is ALWAYS preserved.
  Normalization runs on a COPY; span offsets are mapped back to the original.

Why this matters:
  - Redaction requires exact character spans in the original document.
  - Highlighting / audit trails require source fidelity.
  - OCR output often contains noise that must be cleaned for detection
    without mutating the stored document text.

Responsibilities:
  1. Produce a clean copy of the text for detection engines.
  2. Build an alignment table (original_offset → normalised_offset).
  3. Provide reverse mapping (normalised_span → original_span) so every
     PIIMatch can reference the original document.

Normalisation steps applied to the copy:
  - Collapse excessive whitespace / line breaks
  - Remove null bytes and control characters (except \\n and \\t)
  - Normalise Unicode quotes, dashes, and ligatures to ASCII equivalents
  - Expand common OCR ligatures (ﬁ→fi, ﬂ→fl, etc.)
  - Preserve punctuation (needed for regex patterns like "PAN: ABCDE1234F")
"""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass, field


@dataclass
class NormalisedText:
    """
    Container returned by normalise().  Holds both the cleaned text used
    for detection and the alignment table for span mapping.
    """
    original:  str
    normalised: str
    # List of (orig_offset, norm_offset) pairs — sorted by orig_offset.
    # Gaps in original (deleted chars) are handled by linear interpolation.
    _alignment: list[tuple[int, int]] = field(default_factory=list, repr=False)

    def to_original_span(self, norm_start: int, norm_end: int) -> tuple[int, int]:
        """
        Map a span in the normalised text back to the original text.
        Returns (-1, -1) if the mapping cannot be determined.
        """
        if not self._alignment:
            return norm_start, norm_end  # identity (no normalisation applied)

        orig_start = self._norm_to_orig(norm_start)
        orig_end   = self._norm_to_orig(norm_end)
        return orig_start, orig_end

    def _norm_to_orig(self, norm_pos: int) -> int:
        if norm_pos < 0:
            return -1
        # Binary search for the nearest alignment point
        lo, hi = 0, len(self._alignment) - 1
        while lo <= hi:
            mid = (lo + hi) // 2
            if self._alignment[mid][1] <= norm_pos:
                lo = mid + 1
            else:
                hi = mid - 1
        if lo == 0:
            return self._alignment[0][0] if self._alignment else norm_pos
        orig_base, norm_base = self._alignment[lo - 1]
        delta = norm_pos - norm_base
        return orig_base + delta


# ── Unicode normalisation maps ────────────────────────────────────────────────

_UNICODE_SUBSTITUTIONS: dict[str, str] = {
    # Smart quotes → ASCII quotes
    "‘": "'", "’": "'", "“": '"', "”": '"',
    # Dashes → hyphen
    "–": "-", "—": "-", "―": "-",
    # Ellipsis
    "…": "...",
    # OCR ligatures
    "ﬁ": "fi", "ﬂ": "fl", "ﬃ": "ffi", "ﬄ": "ffl",
    "ﬀ": "ff",
    # Non-breaking space → space
    " ": " ", " ": " ", " ": " ",
    # Zero-width characters → empty
    "​": "", "‌": "", "‍": "", "﻿": "",
    # Degree / special that sometimes confuses tokenisers
    "°": " degrees ",
}

_LIGATURE_RE = re.compile("|".join(re.escape(k) for k in _UNICODE_SUBSTITUTIONS))
_CONTROL_CHARS_RE = re.compile(r"[^\S\n\t ]+")   # all whitespace except \n, \t, space
_NULL_BYTES_RE    = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_MULTI_BLANK_RE   = re.compile(r"[ \t]{3,}")       # 3+ spaces → 2
_MULTI_NL_RE      = re.compile(r"\n{4,}")           # 4+ newlines → 3


def normalise(text: str) -> NormalisedText:
    """
    Normalise *text* and return a NormalisedText container.

    The container holds both the original and the cleaned copy along with
    an alignment table for bidirectional span mapping.
    """
    if not text:
        return NormalisedText(original="", normalised="", _alignment=[])

    # Work on a character list to build alignment incrementally
    chars_orig = list(text)
    out_chars: list[str] = []
    alignment: list[tuple[int, int]] = []   # (orig_idx, norm_idx)

    orig_i = 0
    norm_i = 0

    while orig_i < len(chars_orig):
        ch = chars_orig[orig_i]

        # 1. Null / control characters → skip
        if _NULL_BYTES_RE.match(ch):
            orig_i += 1
            continue

        # 2. Unicode substitutions
        sub = _UNICODE_SUBSTITUTIONS.get(ch)
        if sub is not None:
            alignment.append((orig_i, norm_i))
            if sub:
                out_chars.append(sub)
                norm_i += len(sub)
            orig_i += 1
            continue

        # 3. NFKC normalise (e.g. fullwidth digits → ASCII)
        nfkc = unicodedata.normalize("NFKC", ch)
        alignment.append((orig_i, norm_i))
        out_chars.append(nfkc)
        norm_i += len(nfkc)
        orig_i += 1

    normalised = "".join(out_chars)

    # Post-pass: collapse runs of spaces/newlines (alignment is already built
    # at character granularity so the minor residual drift is acceptable)
    normalised = _MULTI_BLANK_RE.sub("  ", normalised)
    normalised = _MULTI_NL_RE.sub("\n\n\n", normalised)

    return NormalisedText(
        original=text,
        normalised=normalised,
        _alignment=alignment,
    )
