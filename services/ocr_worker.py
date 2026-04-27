#!/usr/bin/env python3
"""
One-shot OCR subprocess worker (Azure Document Intelligence backend).

Usage:
    python -m services.ocr_worker [--boxes] img1 [img2 ...]

Outputs a JSON array (one entry per image) to stdout, then exits.
The parent process (document_parser.py) spawns this script per job.

Each entry:
    {"text": "...", "lines": [[text, [[x,y],[x,y],[x,y],[x,y]]], ...]}
"lines" is populated only when --boxes is passed; otherwise it is [].

Required env vars:
    DOCUMENTINTELLIGENCE_ENDPOINT
    DOCUMENTINTELLIGENCE_API_KEY
"""
from __future__ import annotations

import json
import os
import sys


def _make_client():
    from azure.ai.documentintelligence import DocumentIntelligenceClient
    from azure.core.credentials import AzureKeyCredential
    from azure.core.pipeline.policies import HeadersPolicy

    endpoint = os.environ.get("DOCUMENTINTELLIGENCE_ENDPOINT", "").rstrip("/")
    key = os.environ.get("DOCUMENTINTELLIGENCE_API_KEY", "")
    if not endpoint or not key:
        raise RuntimeError(
            "DOCUMENTINTELLIGENCE_ENDPOINT and DOCUMENTINTELLIGENCE_API_KEY must be set"
        )

    # services.ai.azure.com (Azure AI Foundry) expects the key in the
    # "api-key" header; cognitiveservices.azure.com uses
    # "Ocp-Apim-Subscription-Key" (the SDK default). Override for Foundry.
    if "services.ai.azure.com" in endpoint:
        headers_policy = HeadersPolicy(base_headers={"api-key": key})
        return DocumentIntelligenceClient(
            endpoint, AzureKeyCredential(key),
            headers_policy=headers_policy,
        )
    return DocumentIntelligenceClient(endpoint, AzureKeyCredential(key))


def _process(img_path: str, with_boxes: bool) -> dict:
    client = _make_client()

    with open(img_path, "rb") as f:
        poller = client.begin_analyze_document(
            "prebuilt-read",
            body=f,
            content_type="application/octet-stream",
        )
    result = poller.result()

    if not result.pages:
        return {"text": "", "lines": []}

    all_lines = []
    for page in result.pages:
        if not page.lines:
            continue
        for line in page.lines:
            text = line.content
            if not text or not text.strip():
                continue
            if with_boxes and line.polygon:
                # polygon is a flat list [x0,y0, x1,y1, x2,y2, x3,y3] in pixel coords
                pts = line.polygon
                bbox = [[int(pts[i * 2]), int(pts[i * 2 + 1])] for i in range(4)]
                all_lines.append([text, bbox])
            else:
                all_lines.append([text, []])

    return {
        "text": "\n".join(t for t, _ in all_lines),
        "lines": all_lines if with_boxes else [],
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
