#!/usr/bin/env python3
"""
OCR worker — PaddleOCR dispatcher.

PaddleOCR is the sole OCR engine (in-process singleton, see ocr_engine.py).
Models are loaded once at startup and reused for every request.
"""
from __future__ import annotations

import json
import logging
import sys

logger = logging.getLogger(__name__)


def process_images(img_paths: list[str], with_boxes: bool = False) -> list[dict]:
    """
    OCR a list of image paths via PaddleOCR.
    Returns one result dict per path:
        {"text": str, "lines": [[text, [[x,y]×4]], ...]}
    """
    from services.ocr_engine import run_ocr
    return run_ocr(img_paths, with_boxes=with_boxes)


# ── Legacy CLI entry-point ────────────────────────────────────────────────────

def main():
    args       = sys.argv[1:]
    with_boxes = "--boxes" in args
    paths      = [a for a in args if not a.startswith("--")]

    if not paths:
        print(json.dumps([]))
        return

    results = process_images(paths, with_boxes=with_boxes)
    print(json.dumps(results, ensure_ascii=False))


if __name__ == "__main__":
    main()
