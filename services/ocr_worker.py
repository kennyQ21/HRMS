#!/usr/bin/env python3
"""
OCR worker — thin dispatcher.

When called as a CLI (legacy subprocess path):
    python -m services.ocr_worker [--boxes] img1 [img2 ...]

Backend selection:
  • Azure Document Intelligence if DOCUMENTINTELLIGENCE_ENDPOINT + _API_KEY are set.
  • PaddleOCR (in-process singleton, see services/ocr_engine.py) otherwise.

NOTE: The subprocess path is kept only for Azure DI, whose heavy work is
network I/O, not CPU.  PaddleOCR is called in-process via ocr_engine.py
so models are loaded once and reused — not reloaded per subprocess call.
"""
from __future__ import annotations

import json
import logging
import os
import sys

logger = logging.getLogger(__name__)


# ── Azure DI ──────────────────────────────────────────────────────────────────

def _azure_available() -> bool:
    return bool(
        os.environ.get("DOCUMENTINTELLIGENCE_ENDPOINT", "").strip()
        and os.environ.get("DOCUMENTINTELLIGENCE_API_KEY", "").strip()
    )


def _make_azure_client():
    from azure.ai.documentintelligence import DocumentIntelligenceClient
    from azure.core.credentials import AzureKeyCredential
    from azure.core.pipeline.policies import HeadersPolicy

    endpoint = os.environ["DOCUMENTINTELLIGENCE_ENDPOINT"].rstrip("/")
    key      = os.environ["DOCUMENTINTELLIGENCE_API_KEY"]

    if "services.ai.azure.com" in endpoint:
        headers_policy = HeadersPolicy(base_headers={"api-key": key})
        return DocumentIntelligenceClient(
            endpoint, AzureKeyCredential(key),
            headers_policy=headers_policy,
        )
    return DocumentIntelligenceClient(endpoint, AzureKeyCredential(key))


def _process_azure(img_path: str, with_boxes: bool) -> dict:
    client = _make_azure_client()
    with open(img_path, "rb") as f:
        poller = client.begin_analyze_document(
            "prebuilt-read", body=f, content_type="application/octet-stream",
        )
    result = poller.result()

    if not result.pages:
        return {"text": "", "lines": []}

    all_lines = []
    for page in result.pages:
        for line in (page.lines or []):
            text = (line.content or "").strip()
            if not text:
                continue
            if with_boxes and line.polygon:
                pts  = line.polygon
                bbox = [[int(pts[i * 2]), int(pts[i * 2 + 1])] for i in range(4)]
                all_lines.append([text, bbox])
            else:
                all_lines.append([text, []])

    return {
        "text":  "\n".join(t for t, _ in all_lines),
        "lines": all_lines if with_boxes else [],
    }


# ── Public API (used by document_parser.py) ───────────────────────────────────

def process_images(img_paths: list[str], with_boxes: bool = False) -> list[dict]:
    """
    OCR a list of image paths.  Returns one result dict per path:
        {"text": str, "lines": [[text, [[x,y]×4]], ...]}

    Chooses Azure DI or PaddleOCR automatically.
    """
    if _azure_available():
        results = []
        for p in img_paths:
            try:
                results.append(_process_azure(p, with_boxes))
            except Exception as exc:
                logger.error("[OCR/Azure] %s: %s", p, exc)
                results.append({"text": "", "lines": [], "error": str(exc)})
        return results

    # In-process PaddleOCR — models already loaded in this process
    from services.ocr_engine import run_ocr
    return run_ocr(img_paths, with_boxes=with_boxes)


# ── Legacy CLI entry-point (kept for backward compat / direct invocation) ─────

def main():
    args      = sys.argv[1:]
    with_boxes = "--boxes" in args
    paths      = [a for a in args if not a.startswith("--")]

    if not paths:
        print(json.dumps([]))
        return

    results = process_images(paths, with_boxes=with_boxes)
    print(json.dumps(results, ensure_ascii=False))


if __name__ == "__main__":
    main()
