"""
services/ocr_validator.py
-------------------------
Minimal OCR/entity/bbox validator.

Only three checks:
  1. Redactable image entities have a bbox.
  2. Entity value overlaps OCR line text for its bbox.
  3. Low OCR confidence requires manual review.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any


@dataclass
class OCRValidationReport:
    passed: bool = True
    issues: list[str] = field(default_factory=list)
    manual_review_required: bool = False

    def add_issue(self, code: str) -> None:
        self.issues.append(code)
        self.passed = False


def validate_ocr_alignment(
    entities: list,
    ocr_lines: list,
    ocr_quality: dict[str, Any] | None = None,
) -> OCRValidationReport:
    """Run the three OCR integrity checks and return a small report."""
    report = OCRValidationReport()

    indexed_lines = [_coerce_line(line) for line in ocr_lines]
    indexed_lines = [line for line in indexed_lines if line["text"] and line["bbox"]]

    for entity in entities:
        if not _requires_redaction(entity):
            continue

        bbox = _entity_bbox(entity)
        if not bbox:
            report.add_issue("missing_bbox")
            continue

        overlapping_text = " ".join(
            line["text"] for line in indexed_lines
            if _bbox_overlaps(bbox, line["bbox"])
        )
        if overlapping_text and not _value_overlaps_text(entity.value, overlapping_text):
            report.add_issue("ocr_text_mismatch")

    avg_conf = 1.0
    if ocr_quality:
        avg_conf = float(ocr_quality.get("avg_confidence", 1.0) or 0.0)
    if avg_conf < 0.4:
        report.manual_review_required = True
        report.add_issue("manual_review_required")

    return report


def _requires_redaction(entity: Any) -> bool:
    metadata = getattr(entity, "metadata", {}) or {}
    return bool(metadata.get("requires_redaction", True))


def _entity_bbox(entity: Any):
    metadata = getattr(entity, "metadata", {}) or {}
    return getattr(entity, "bbox", None) or metadata.get("bbox")


def _coerce_line(line: Any) -> dict[str, Any]:
    if isinstance(line, dict):
        return {
            "text": str(line.get("text", "")),
            "bbox": line.get("bbox"),
        }
    if isinstance(line, (tuple, list)) and len(line) >= 2:
        return {"text": str(line[0]), "bbox": line[1]}
    return {"text": "", "bbox": None}


def _bbox_bounds(bbox) -> tuple[float, float, float, float] | None:
    if not bbox:
        return None
    try:
        xs = [float(point[0]) for point in bbox if len(point) >= 2]
        ys = [float(point[1]) for point in bbox if len(point) >= 2]
    except Exception:
        return None
    if not xs or not ys:
        return None
    return min(xs), min(ys), max(xs), max(ys)


def _bbox_overlaps(a, b) -> bool:
    ab = _bbox_bounds(a)
    bb = _bbox_bounds(b)
    if not ab or not bb:
        return False
    ax1, ay1, ax2, ay2 = ab
    bx1, by1, bx2, by2 = bb
    return not (ax2 < bx1 or bx2 < ax1 or ay2 < by1 or by2 < ay1)


def _norm(text: str) -> str:
    return re.sub(r"[\W_]+", "", text or "", flags=re.UNICODE).casefold()


def _value_overlaps_text(value: str, text: str) -> bool:
    value_norm = _norm(value)
    text_norm = _norm(text)
    if not value_norm:
        return True
    if value_norm in text_norm:
        return True

    value_digits = re.sub(r"\D", "", value or "")
    text_digits = re.sub(r"\D", "", text or "")
    return bool(len(value_digits) >= 6 and value_digits in text_digits)
