#!/usr/bin/env python3
"""
One-shot OCR subprocess worker (EasyOCR backend).

Usage:
    python -m services.ocr_worker [--boxes] img1 [img2 ...]

Outputs a JSON array (one entry per image) to stdout, then exits.
The parent process (document_parser.py) spawns this script per job;
if OCR crashes the child dies but the parent/uvicorn survives.

Each entry:
    {"text": "...", "lines": [[text, [[x,y],[x,y],[x,y],[x,y]]], ...]}
"lines" is populated only when --boxes is passed; otherwise it is [].
"""
from __future__ import annotations

import json
import os
import sys

_MAX_SIDE = 4096  # resize before OCR to keep memory manageable


def _resize(img):
    """Return (resized_img, scale_x, scale_y). scale_* map OCR coords back to original."""
    import cv2

    h, w = img.shape[:2]
    if max(h, w) <= _MAX_SIDE:
        return img, 1.0, 1.0
    scale = _MAX_SIDE / max(h, w)
    nw, nh = max(1, int(w * scale)), max(1, int(h * scale))
    return cv2.resize(img, (nw, nh), interpolation=cv2.INTER_AREA), w / nw, h / nh


def _load_engine():
    import easyocr

    # gpu=False: ARM64 containers typically have no CUDA GPU.
    # verbose=False: suppress EasyOCR's download/progress output to stderr.
    return easyocr.Reader(["en"], gpu=False, verbose=False)


def _process(engine, img_path: str, with_boxes: bool) -> dict:
    import cv2

    img = cv2.imread(img_path)
    if img is None:
        return {"text": "", "lines": []}

    img_ocr, sx, sy = _resize(img)

    # readtext returns [(bbox, text, confidence), ...]
    # bbox = [[x1,y1],[x2,y1],[x2,y2],[x1,y2]] in img_ocr pixel space
    results = engine.readtext(img_ocr)

    lines = []
    for bbox, text, _conf in results:
        if not (text and text.strip()):
            continue
        if with_boxes:
            # Scale bbox back to original image coordinates for redaction
            if sx != 1.0 or sy != 1.0:
                bbox = [[int(p[0] * sx), int(p[1] * sy)] for p in bbox]
            lines.append([text.strip(), bbox])
        else:
            lines.append([text.strip(), []])

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
