#!/usr/bin/env python3
"""
One-shot OCR subprocess worker.

Usage:
    python -m services.ocr_worker [--boxes] img1 [img2 ...]

Outputs a JSON array (one entry per image) to stdout, then exits.
The parent process spawns this script for each OCR job; if PaddleOCR
segfaults (SIGSEGV, exit 139) the child dies but the parent survives.

Each entry:
    {"text": "...", "lines": [[text, [[x,y],[x,y],[x,y],[x,y]]], ...]}
"lines" is populated only when --boxes is passed; otherwise it is [].
"""
from __future__ import annotations

import json
import os
import sys

_MAX_SIDE = 3000  # pre-resize to stay below PaddleOCR's 4000-px crash threshold


def _resize(img, max_side: int = _MAX_SIDE):
    import cv2

    h, w = img.shape[:2]
    if max(h, w) <= max_side:
        return img, 1.0, 1.0
    scale = max_side / max(h, w)
    nw, nh = max(1, int(w * scale)), max(1, int(h * scale))
    return cv2.resize(img, (nw, nh), interpolation=cv2.INTER_AREA), w / nw, h / nh


def _load_engine():
    os.environ.setdefault("PADDLE_PDX_DISABLE_MODEL_SOURCE_CHECK", "True")
    os.environ.setdefault("OMP_NUM_THREADS", "1")
    os.environ.setdefault("OPENBLAS_NUM_THREADS", "1")
    from paddleocr import PaddleOCR

    return PaddleOCR(
        text_detection_model_name="PP-OCRv5_mobile_det",
        text_recognition_model_name="PP-OCRv5_mobile_rec",
        use_doc_orientation_classify=False,
        use_textline_orientation=False,
        use_doc_unwarping=False,
        enable_mkldnn=False,
    )


def _process(engine, img_path: str, with_boxes: bool) -> dict:
    import cv2

    img = cv2.imread(img_path)
    if img is None:
        return {"text": "", "lines": []}

    img_ocr, sx, sy = _resize(img)
    results = list(engine.predict(img_ocr))

    lines = []
    for r in results:
        for t, p in zip(r.get("rec_texts", []), r.get("dt_polys", [])):
            if t and t.strip():
                bbox = p.tolist() if hasattr(p, "tolist") else list(p)
                if sx != 1.0 or sy != 1.0:
                    bbox = [[int(pt[0] * sx), int(pt[1] * sy)] for pt in bbox]
                lines.append([t.strip(), bbox])

    return {
        "text": "\n".join(t for t, _ in lines),
        "lines": lines if with_boxes else [],
    }


def main():
    args = sys.argv[1:]
    with_boxes = "--boxes" in args
    paths = [a for a in args if not a.startswith("--")]

    if not paths:
        print(json.dumps([]))
        return

    engine = _load_engine()
    results = []
    for p in paths:
        try:
            results.append(_process(engine, p, with_boxes))
        except Exception as exc:
            results.append({"text": "", "lines": [], "error": str(exc)})

    print(json.dumps(results))


if __name__ == "__main__":
    main()
