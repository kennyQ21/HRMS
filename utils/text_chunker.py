"""
utils/text_chunker.py
----------------------
Sentence-aware text chunking for NLP engines.

Replaces the ad-hoc chunking in gliner_engine.py and llm_engine.py
with a single, consistent implementation.

Rules:
  - max_chunk_chars = 1200 (GLiNER token limit consideration)
  - Break at sentence boundaries (". " or "\n")
  - Overlap only at sentence boundaries (not arbitrary chars)
  - Minimum overlap: 1 sentence from previous chunk
"""

from __future__ import annotations

import re
from typing import Optional


def chunk_text(
    text: str,
    max_chars: int = 1200,
    min_overlap_sentences: int = 1,
) -> list[str]:
    """
    Split *text* into chunks of at most *max_chars*, breaking at
    sentence boundaries. Overlap is achieved by including the last
    *min_overlap_sentences* sentences from the previous chunk.

    Returns a list of text chunks.
    """
    if len(text) <= max_chars:
        return [text]

    # Split into sentences using lightweight regex
    # Handles: period+space, newline, question mark, exclamation
    sentences = re.split(r"(?<=[.!?。])\s+|\n+", text)
    sentences = [s for s in sentences if s.strip()]

    if not sentences:
        return [text]

    chunks: list[str] = []
    current_chunk: list[str] = []
    current_len = 0

    for sentence in sentences:
        sent_len = len(sentence) + 1  # +1 for the joining space

        # If adding this sentence exceeds max_chars, finalize current chunk
        if current_len + sent_len > max_chars and current_chunk:
            chunk_text_str = " ".join(current_chunk)
            chunks.append(chunk_text_str)

            # Start new chunk with overlap: last N sentences from previous
            overlap_start = max(0, len(current_chunk) - min_overlap_sentences)
            current_chunk = current_chunk[overlap_start:]
            current_len = sum(len(s) + 1 for s in current_chunk)

        current_chunk.append(sentence)
        current_len += sent_len

    # Don't forget the last chunk
    if current_chunk:
        chunk_text_str = " ".join(current_chunk)
        chunks.append(chunk_text_str)

    return chunks
