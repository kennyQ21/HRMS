#!/usr/bin/env python3
"""
One-shot OCR subprocess worker (Tesseract backend via pytesseract).

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
import sys
from collections import defaultdict

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


def _process(img_path: str, with_boxes: bool) -> dict:
    import cv2
    import pytesseract
    from PIL import Image

    img = cv2.imread(img_path)
    if img is None:
        return {"text": "", "lines": []}

    img_ocr, sx, sy = _resize(img)
    pil_img = Image.fromarray(cv2.cvtColor(img_ocr, cv2.COLOR_BGR2RGB))

    if not with_boxes:
        text = pytesseract.image_to_string(pil_img).strip()
        return {"text": text, "lines": []}

    # Word-level data; group by (block, paragraph, line) → line-level entries
    data = pytesseract.image_to_data(pil_img, output_type=pytesseract.Output.DICT)

    # Each group accumulates the words and the union bounding rect for the line.
    groups: dict = defaultdict(lambda: {"words": [], "x1": [], "y1": [], "x2": [], "y2": []})
    for i in range(len(data["text"])):
        word = data["text"][i].strip()
        if not word or int(data["conf"][i]) < 0:
            continue
        key = (data["block_num"][i], data["par_num"][i], data["line_num"][i])
        x, y, w, h = data["left"][i], data["top"][i], data["width"][i], data["height"][i]
        groups[key]["words"].append(word)
        groups[key]["x1"].append(x)
        groups[key]["y1"].append(y)
        groups[key]["x2"].append(x + w)
        groups[key]["y2"].append(y + h)

    lines = []
    for key in sorted(groups):
        g = groups[key]
        line_text = " ".join(g["words"])
        # Scale bbox back to original image coordinates
        x1 = int(min(g["x1"]) * sx)
        y1 = int(min(g["y1"]) * sy)
        x2 = int(max(g["x2"]) * sx)
        y2 = int(max(g["y2"]) * sy)
        bbox = [[x1, y1], [x2, y1], [x2, y2], [x1, y2]]
        lines.append([line_text, bbox])

    return {
        "text": "\n".join(t for t, _ in lines),
        "lines": lines,
    }


def main():
    args = sys.argv[1:]
    with_boxes = "--boxes" in args
    paths = [a for a in args if not a.startswith("--")]

    if not paths:
        print(json.dumps([]))
        return

    results = []
    for p in paths:
        try:
            results.append(_process(p, with_boxes))
        except Exception as exc:
            results.append({"text": "", "lines": [], "error": str(exc)})

    print(json.dumps(results))


if __name__ == "__main__":
    main()
