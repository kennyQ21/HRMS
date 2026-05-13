"""
services/ocr_engine.py
-----------------------
In-process OCR engine — PaddleOCR singleton loaded once per server lifetime.

Why in-process instead of subprocess?
  The old ocr_worker.py spawned a new Python child for every OCR job.
  Each child re-loaded PaddleOCR's neural-network weights (~600 MB) from
  scratch.  Five concurrent image uploads = five simultaneous model loads
  = 3–5 GB RAM spike = Mac crash.

  Here the models are loaded once via @lru_cache and reused for every
  subsequent call.  Memory stays flat after the first warm-up.

Performance knobs used:
  use_doc_orientation_classify=False  — skips doc-level rotation model
  use_doc_unwarping=False             — skips perspective-correction model
  use_textline_orientation=False      — skips per-line flip model
  These three models are only useful for photos of documents taken at an
  angle; scanned images are already straight.  Disabling them cuts cold
  start time by ~60 % and RAM by ~300 MB.

  Images are also downscaled to max 2000 px on the long side before
  inference so the detection network never processes giant bitmaps.

Output format (same as the old subprocess worker):
  [{"text": "...", "lines": [[text, [[x,y]×4]], ...]}, ...]
  "lines" is non-empty only when with_boxes=True.
"""
from __future__ import annotations

import logging
import os
from functools import lru_cache
from typing import List

logger = logging.getLogger(__name__)

# Maximum long-side pixel length sent to PaddleOCR.
# 2000 px is large enough for A4 at 200 dpi; anything bigger just wastes RAM.
_MAX_PX = 2000


@lru_cache(maxsize=1)
def _get_ocr():
    """Load PaddleOCR once per process and cache it."""
    from paddleocr import PaddleOCR  # heavy import — deferred intentionally

    logger.info("[OCR] Loading PaddleOCR mobile models (first call only)…")
    ocr = PaddleOCR(
        # Mobile models: already cached at ~/.paddlex/official_models/
        # 4.8 MB det + 7.7 MB rec — ~10x lighter than server models (84+81 MB)
        text_detection_model_name="PP-OCRv5_mobile_det",
        text_recognition_model_name="en_PP-OCRv5_mobile_rec",
        # Disable heavy auxiliary models not needed for scanned docs
        use_doc_orientation_classify=False,   # no doc-rotation model (6.6 MB)
        use_doc_unwarping=False,              # no perspective model (31 MB)
        use_textline_orientation=False,       # no per-line flip model (6.6 MB)
    )
    logger.info("[OCR] PaddleOCR ready.")
    return ocr


def _resize_if_needed(img_path: str) -> str:
    """
    Return a (possibly temp) path to an image whose long side ≤ _MAX_PX.
    Returns the original path unchanged if already within bounds.
    """
    try:
        from PIL import Image
        import tempfile

        img = Image.open(img_path)
        w, h = img.size
        if max(w, h) <= _MAX_PX:
            return img_path                   # already small enough

        scale = _MAX_PX / max(w, h)
        new_w, new_h = int(w * scale), int(h * scale)
        img = img.resize((new_w, new_h), Image.LANCZOS)

        suffix = os.path.splitext(img_path)[1] or ".jpg"
        tmp = tempfile.NamedTemporaryFile(delete=False, suffix=suffix)
        img.save(tmp.name)
        logger.debug("[OCR] Resized %s (%dx%d → %dx%d)", img_path, w, h, new_w, new_h)
        return tmp.name
    except Exception as exc:
        logger.warning("[OCR] Resize failed for %s: %s — using original", img_path, exc)
        return img_path


def _parse_result(raw) -> List[dict]:
    """
    Convert PaddleOCR 3.x predict() output to our internal line format:
      [{"text": str, "bbox": [[x,y],[x,y],[x,y],[x,y]]}, ...]
    """
    lines = []
    if not raw:
        return lines

    for page in raw:
        if not page:
            continue
        # PaddleOCR 3.x result objects are subscriptable dict-like objects
        try:
            texts  = page["rec_texts"]
            scores = page["rec_scores"]
            polys  = page["dt_polys"]
        except (KeyError, TypeError):
            # Fallback: older dict format  {"dt_boxes": ..., "rec_res": ...}
            try:
                texts  = [r[0] for r in page.get("rec_res", [])]
                scores = [r[1] for r in page.get("rec_res", [])]
                polys  = page.get("dt_boxes", [])
            except Exception:
                continue

        for text, score, poly in zip(texts, scores, polys):
            text = (text or "").strip()
            if not text or score < 0.15:
                continue
            # poly: [[x1,y1],[x2,y2],[x3,y3],[x4,y4]] (already int-like)
            bbox = [[int(pt[0]), int(pt[1])] for pt in poly]
            lines.append({"text": text, "bbox": bbox, "confidence": float(score)})

    return lines


def run_ocr(img_paths: List[str], with_boxes: bool = False) -> List[dict]:
    """
    Run OCR on a list of image paths in-process.

    Returns one entry per path:
        {"text": str, "lines": [[text, [[x,y]×4]], ...]}
    "lines" is populated only when with_boxes=True.

    Each image is processed with a hard timeout (OCR_TIMEOUT_SECONDS).
    On timeout: returns empty result for that image, continues with the rest.
    """
    from constants import OCR_TIMEOUT_SECONDS
    from services.utils.timeout import run_with_timeout

    ocr = _get_ocr()
    results = []

    for img_path in img_paths:
        resized_path = _resize_if_needed(img_path)
        tmp_created  = (resized_path != img_path)

        try:
            raw = run_with_timeout(ocr.predict, OCR_TIMEOUT_SECONDS, resized_path)
            if raw is None:
                # OCR timed out for this image
                logger.warning("[OCR] Timed out after %ds for %s", OCR_TIMEOUT_SECONDS, img_path)
                results.append({"text": "", "lines": [], "error": "timeout",
                                 "ocr_quality": {"char_count": 0, "line_count": 0,
                                                 "avg_confidence": 0.0,
                                                 "manual_review_required": True}})
                continue
            lines = _parse_result(raw)

            text = "\n".join(ln["text"] for ln in lines)
            out_lines = [[ln["text"], ln["bbox"]] for ln in lines] if with_boxes else []

            # Compute OCR quality metrics for compliance escalation
            avg_conf = sum(ln.get("confidence", 0.5) for ln in lines) / max(len(lines), 1)
            ocr_quality = {
                "char_count": len(text),
                "line_count": len(lines),
                "avg_confidence": round(avg_conf, 3),
                "manual_review_required": len(text) < 50 or avg_conf < 0.4,
            }
            results.append({"text": text, "lines": out_lines, "ocr_quality": ocr_quality})
            logger.info("[OCR] %s → %d chars, %d lines, avg_conf=%.2f, review=%s",
                        os.path.basename(img_path), len(text), len(lines),
                        avg_conf, ocr_quality["manual_review_required"])

        except Exception as exc:
            logger.error("[OCR] Failed on %s: %s", img_path, exc)
            results.append({"text": "", "lines": [], "error": str(exc),
                             "ocr_quality": {"char_count": 0, "line_count": 0,
                                             "avg_confidence": 0.0,
                                             "manual_review_required": True}})

        finally:
            if tmp_created:
                try:
                    os.remove(resized_path)
                except OSError:
                    pass

    return results
