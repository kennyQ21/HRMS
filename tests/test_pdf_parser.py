#!/usr/bin/env python3
"""
test_pdf_parser.py
------------------
Standalone smoke-test for PDFParser (PaddleOCR backend).

Run from the project root:
    python test_pdf_parser.py

Requires the venv to be active with paddlepaddle, paddleocr, pdf2image,
opencv-python, and PyPDF2 installed.
"""

import logging
import sys
import textwrap
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

# ── Configure logging so PaddleOCR's own messages don't swamp the output ──────
logging.basicConfig(
    level=logging.INFO,
    format="%(levelname)-8s %(name)s: %(message)s",
)
# Silence the very chatty paddle internals
for noisy in ("ppocr", "paddle", "PIL"):
    logging.getLogger(noisy).setLevel(logging.WARNING)

PDF_PATH = Path(__file__).resolve().parent.parent / "Scanned-receipt-example-file.pdf"

SEPARATOR = "=" * 70


def _section(title: str) -> None:
    print(f"\n{SEPARATOR}")
    print(f"  {title}")
    print(SEPARATOR)


def run_test() -> None:
    _section("Environment check")

    # Verify the PDF exists
    if not PDF_PATH.exists():
        print(f"[FAIL] PDF not found: {PDF_PATH}")
        sys.exit(1)
    print(f"[OK]  PDF found  : {PDF_PATH}  ({PDF_PATH.stat().st_size / 1024:.1f} KB)")

    # Import the parser (this also validates the package structure)
    try:
        from parsers.unstructured.document_parser import PDFParser
        print("[OK]  PDFParser imported successfully")
    except ImportError as exc:
        print(f"[FAIL] Import error: {exc}")
        sys.exit(1)

    # ── Initialisation ────────────────────────────────────────────────────────
    _section("Initialising PDFParser (PaddleOCR model load)")
    t0 = time.perf_counter()
    try:
        parser = PDFParser(lang="en")
        init_s = time.perf_counter() - t0
        print(f"[OK]  Parser ready in {init_s:.2f} s")
    except Exception as exc:
        print(f"[FAIL] Initialisation failed: {exc}")
        raise

    # ── Text-layer extraction ─────────────────────────────────────────────────
    _section("Step 1 — PyPDF2 text-layer extraction")
    t1 = time.perf_counter()
    try:
        layer_text = parser._extract_text_layer(str(PDF_PATH))
        layer_s = time.perf_counter() - t1
        char_count = len(layer_text.strip())
        print(f"[OK]  Completed in {layer_s:.2f} s")
        print(f"      Characters extracted : {char_count}")
        if char_count < 100:
            print("      ↳ Sparse text layer — scanned PDF confirmed, OCR will be used.")
        else:
            print("      ↳ Rich text layer — OCR fallback will be skipped.")
    except Exception as exc:
        print(f"[FAIL] Text-layer extraction failed: {exc}")
        layer_text = ""

    # ── OCR extraction ────────────────────────────────────────────────────────
    _section("Step 2 — PaddleOCR extraction (all image variants)")
    t2 = time.perf_counter()
    try:
        ocr_text = parser._extract_text_via_ocr(str(PDF_PATH))
        ocr_s = time.perf_counter() - t2
        print(f"[OK]  Completed in {ocr_s:.2f} s")
        print(f"      Characters extracted : {len(ocr_text.strip())}")
    except Exception as exc:
        print(f"[FAIL] OCR extraction failed: {exc}")
        ocr_text = ""

    # ── Full parse() round-trip ───────────────────────────────────────────────
    _section("Step 3 — Full parse() round-trip")
    t3 = time.perf_counter()
    try:
        result = parser.parse(str(PDF_PATH))
        parse_s = time.perf_counter() - t3

        content   = result["data"][0]["content"]
        metadata  = result["metadata"]
        valid     = parser.validate(result)

        print(f"[OK]  parse() completed in {parse_s:.2f} s")
        print(f"      Parser tag    : {metadata['parser']}")
        print(f"      Content chars : {len(content.strip())}")
        print(f"      validate()    : {'PASS' if valid else 'FAIL'}")
    except Exception as exc:
        print(f"[FAIL] parse() failed: {exc}")
        raise

    # ── Extracted text preview ────────────────────────────────────────────────
    _section("Extracted Text Preview (first 2 000 chars)")
    preview = content.strip()[:2000]
    wrapped = textwrap.fill(preview, width=80)
    print(wrapped)

    # ── Summary ───────────────────────────────────────────────────────────────
    _section("Test Summary")
    total_s = time.perf_counter() - t0
    print(f"  PDF size          : {PDF_PATH.stat().st_size / 1024:.1f} KB")
    print(f"  Model init        : {init_s:.2f} s")
    print(f"  Text-layer step   : {layer_s:.2f} s  ({len(layer_text.strip())} chars)")
    print(f"  OCR step          : {ocr_s:.2f} s  ({len(ocr_text.strip())} chars)")
    print(f"  Full parse()      : {parse_s:.2f} s  ({len(content.strip())} chars)")
    print(f"  Total wall time   : {total_s:.2f} s")
    print(f"  validate()        : {'PASS ✓' if valid else 'FAIL ✗'}")
    print(SEPARATOR)


if __name__ == "__main__":
    run_test()
