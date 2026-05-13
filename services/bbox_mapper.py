"""
services/bbox_mapper.py
------------------------
Maps semantic entity spans to OCR bounding box coordinates.

Pipeline:
  entity span
      ↓ overlapping OCR lines
      ↓ merge line boxes
      ↓ entity bbox

This is critical for image redaction — semantic entities (from GLiNER/Qwen)
don't have bbox coordinates by default, but OCR lines do. By finding
which OCR lines overlap with an entity's text span, we can derive
the entity's bounding box for redaction.
"""

from __future__ import annotations

import logging
from typing import Optional

logger = logging.getLogger(__name__)


def map_entities_to_bboxes(
    entities: list,
    ocr_lines: list,
    full_text: str = "",
) -> list:
    """
    Map semantic entity spans to OCR bounding box coordinates.

    For each entity that lacks a bbox, find the OCR lines whose text
    overlaps with the entity's value in the full document text, then
    merge those line bboxes into a single entity bbox.

    Args:
        entities:  List of ResolvedEntity objects (may or may not have bbox)
        ocr_lines: List of (text, bbox) tuples from OCR engine
        full_text: Full document text (for position-based matching)

    Returns:
        The same entities list with bbox metadata added where possible.
    """
    if not ocr_lines or not entities:
        return entities

    # Build OCR line position index: find where each OCR line starts
    # in the full document text
    ocr_line_positions: list[tuple[int, int, list]] = []  # (start, end, bbox)
    search_start = 0

    for line in ocr_lines:
        line_text, bbox = _coerce_ocr_line(line)
        if not line_text or not line_text.strip():
            continue
        # Find this line's position in the full text
        pos = full_text.find(line_text.strip(), search_start)
        if pos >= 0:
            ocr_line_positions.append((pos, pos + len(line_text.strip()), bbox))
            search_start = pos + len(line_text.strip())
        else:
            # Try fuzzy: find by first few words
            words = line_text.strip().split()[:3]
            if words:
                snippet = " ".join(words)
                pos = full_text.find(snippet, search_start)
                if pos >= 0:
                    ocr_line_positions.append((pos, pos + len(line_text.strip()), bbox))
                    search_start = pos + len(snippet)

    if not ocr_line_positions:
        logger.debug("[BBOX] No OCR line positions mapped")
        return entities

    mapped_count = 0
    for entity in entities:
        # Skip if already has bbox
        if entity.metadata and entity.metadata.get("bbox"):
            continue

        # Only map entities that have a known span position
        if entity.start < 0 or entity.end < 0:
            continue
        _assert_normalized_span(entity, full_text)

        # Find OCR lines that overlap with this entity's span
        overlapping_bboxes = []
        for line_start, line_end, bbox in ocr_line_positions:
            # Check for overlap
            if line_start <= entity.end and line_end >= entity.start:
                overlapping_bboxes.append(bbox)

        if overlapping_bboxes:
            # Merge overlapping bboxes into one
            merged_bbox = _merge_bboxes(overlapping_bboxes)
            if not entity.metadata:
                entity.metadata = {}
            entity.metadata["bbox"] = merged_bbox
            mapped_count += 1

    if mapped_count:
        logger.info("[BBOX] Mapped %d entities to OCR bounding boxes", mapped_count)

    return entities


def _coerce_ocr_line(line) -> tuple[str, list]:
    if isinstance(line, dict):
        return str(line.get("text", "")), line.get("bbox") or []
    if isinstance(line, (tuple, list)) and len(line) >= 2:
        return str(line[0]), line[1]
    return "", []


def _assert_normalized_span(entity, full_text: str) -> None:
    """Ensure bbox mapping receives normalised-coordinate spans."""
    if not full_text:
        return
    if entity.start < 0 or entity.end < 0:
        return
    if entity.end > len(full_text) or entity.start > entity.end:
        raise AssertionError(
            f"bbox span outside normalized text for {entity.pii_type}: "
            f"{entity.start}:{entity.end}"
        )

    span_text = full_text[entity.start:entity.end]
    span_norm = _span_norm(span_text)
    value_norm = _span_norm(entity.value)
    if value_norm and value_norm not in span_norm and span_norm not in value_norm:
        raise AssertionError(
            f"bbox span/value mismatch for {entity.pii_type}: "
            f"{entity.start}:{entity.end}"
        )


def _span_norm(text: str) -> str:
    import re
    return re.sub(r"[\W_]+", "", text or "", flags=re.UNICODE).casefold()


def _merge_bboxes(bboxes: list) -> list:
    """
    Merge multiple bounding boxes into one encompassing box.

    Each bbox is [[x1,y1],[x2,y2],[x3,y3],[x4,y4]] (4 corners).
    Returns the minimal enclosing rectangle as 4 corner points.
    """
    if not bboxes:
        return []

    if len(bboxes) == 1:
        return bboxes[0]

    # Collect all x and y coordinates
    all_x = []
    all_y = []
    for bbox in bboxes:
        if not bbox or len(bbox) < 4:
            continue
        for point in bbox:
            if len(point) >= 2:
                all_x.append(int(point[0]))
                all_y.append(int(point[1]))

    if not all_x or not all_y:
        return bboxes[0] if bboxes else []

    min_x = min(all_x)
    max_x = max(all_x)
    min_y = min(all_y)
    max_y = max(all_y)

    # Add small padding for redaction coverage
    pad = 2
    return [
        [min_x - pad, min_y - pad],
        [max_x + pad, min_y - pad],
        [max_x + pad, max_y + pad],
        [min_x - pad, max_y + pad],
    ]
