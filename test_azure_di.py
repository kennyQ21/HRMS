#!/usr/bin/env python3
"""
Quick test for Azure Document Intelligence outside Docker.

Usage:
    python test_azure_di.py [image_path]

If no image_path is given, extracts the first JPG from sample.zip.
Reads credentials from .env (DOCUMENTINTELLIGENCE_ENDPOINT / DOCUMENTINTELLIGENCE_API_KEY).
"""
import io
import json
import os
import sys
import tempfile
import zipfile
from pathlib import Path

# Force UTF-8 output on Windows consoles
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")

from dotenv import load_dotenv

load_dotenv(Path(__file__).parent / ".env")

endpoint = os.environ.get("DOCUMENTINTELLIGENCE_ENDPOINT", "").rstrip("/")
key = os.environ.get("DOCUMENTINTELLIGENCE_API_KEY", "")

if not endpoint or not key:
    sys.exit("ERROR: DOCUMENTINTELLIGENCE_ENDPOINT and DOCUMENTINTELLIGENCE_API_KEY must be set in .env")

print(f"Endpoint : {endpoint}")
print(f"Key      : {key[:8]}{'*' * (len(key) - 8)}")
print()

# ── Resolve image ──────────────────────────────────────────────────────────────

if len(sys.argv) > 1:
    img_path = sys.argv[1]
    tmp_dir = None
else:
    zip_path = Path(__file__).parent / "sample.zip"
    if not zip_path.exists():
        sys.exit("ERROR: sample.zip not found and no image path provided")
    tmp_dir = tempfile.mkdtemp()
    with zipfile.ZipFile(zip_path) as zf:
        zf.extractall(tmp_dir)
    imgs = sorted(Path(tmp_dir).glob("**/*.jpg"))
    if not imgs:
        sys.exit("ERROR: no JPG found in sample.zip")
    img_path = str(imgs[0])
    print(f"Using    : {Path(img_path).name} (from sample.zip)")

print(f"Image    : {img_path}")
print()

# ── Call Azure Document Intelligence ──────────────────────────────────────────

from azure.ai.documentintelligence import DocumentIntelligenceClient
from azure.core.credentials import AzureKeyCredential
from azure.core.exceptions import HttpResponseError
from azure.core.pipeline.policies import HeadersPolicy

# Foundry (services.ai.azure.com) needs api-key header; standalone DI uses
# Ocp-Apim-Subscription-Key (SDK default). Inject api-key for both to be safe.
headers_policy = HeadersPolicy(base_headers={"api-key": key})
client = DocumentIntelligenceClient(
    endpoint, AzureKeyCredential(key), headers_policy=headers_policy
)

print("Calling prebuilt-read model...")
try:
    with open(img_path, "rb") as f:
        poller = client.begin_analyze_document(
            "prebuilt-read",
            body=f,
            content_type="application/octet-stream",
        )
    result = poller.result()
except HttpResponseError as e:
    sys.exit(f"Azure error: HTTP {e.status_code} — {e}")

# ── Print results ──────────────────────────────────────────────────────────────

pages = result.pages or []
print(f"Pages    : {len(pages)}")
print()

all_lines = []
for page in pages:
    for line in page.lines or []:
        if not line.content or not line.content.strip():
            continue
        pts = line.polygon or []
        if len(pts) >= 8:
            bbox = [[int(pts[i * 2]), int(pts[i * 2 + 1])] for i in range(4)]
        else:
            bbox = []
        all_lines.append({"text": line.content, "bbox": bbox})

print(f"Lines    : {len(all_lines)}")
print()
print("--- Extracted text ---")
for l in all_lines:
    print(l["text"].encode("utf-8", errors="replace").decode("utf-8"))
print("--- End ---")
print()
print("--- First 3 lines with bboxes ---")
print(json.dumps(all_lines[:3], indent=2))
