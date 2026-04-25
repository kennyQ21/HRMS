#!/usr/bin/env python3
"""
Smoke test for image OCR + PII detection on files under sample/.

Generates:
  sample/output/image_scan_report.csv
"""

from __future__ import annotations

import csv
import json
import logging
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from parsers.unstructured.document_parser import ImageParser
from services.pii_service import detect_pii, select_primary_pii

logging.basicConfig(
    level=logging.INFO,
    format="%(levelname)-8s %(name)s: %(message)s",
)
for noisy in ("ppocr", "paddle", "PIL"):
    logging.getLogger(noisy).setLevel(logging.WARNING)

IMAGE_EXTENSIONS = {".jpg", ".jpeg", ".png", ".bmp", ".tif", ".tiff", ".webp"}
REPORT_COLUMNS = [
    "filename",
    "status",
    "ocr_char_count",
    "primary_pii_type",
    "primary_pii_count",
    "pii_counts_json",
    "pii_samples_json",
    "error",
]

DISPLAY_PII_TYPE = {
    "name": "PERSON",
    "organization": "ORG",
    "address": "ADDRESS",
    "pan": "PAN",
    "aadhaar": "AADHAAR",
    "voter_id": "VOTER_ID",
    "phone": "PHONE",
    "email": "EMAIL",
    "credit_card": "CREDIT_CARD",
    "dob": "DOB",
    "expiry": "EXPIRY",
    "cvv": "CVV",
}


def _discover_images(sample_dir: Path) -> list[Path]:
    return sorted(
        p for p in sample_dir.iterdir()
        if p.is_file() and p.suffix.lower() in IMAGE_EXTENSIONS
    )


def _mask_fallback(value: str) -> str:
    compact = re.sub(r"\s+", " ", value).strip()
    if len(compact) <= 2:
        return "***"
    return compact[:2] + "***"


def _mask_value(pii_type: str, value: str) -> str:
    compact = re.sub(r"\s+", " ", value).strip()
    if not compact:
        return "***"

    if pii_type == "pan":
        token = re.sub(r"\W", "", compact).upper()
        if len(token) >= 10:
            return token[:5] + "****" + token[-1]
        return _mask_fallback(compact)

    if pii_type == "aadhaar":
        digits = re.sub(r"\D", "", compact)
        if len(digits) >= 12:
            token = digits[:12]
            return f"{token[:4]} **** {token[-4:]}"
        return _mask_fallback(compact)

    if pii_type == "email" and "@" in compact:
        local, domain = compact.split("@", 1)
        local_head = local[:2] if local else ""
        return f"{local_head}***@{domain}"

    if pii_type == "phone":
        digits = re.sub(r"\D", "", compact)
        if len(digits) >= 10:
            token = digits[-10:]
            return token[:2] + "******" + token[-2:]
        return _mask_fallback(compact)

    if pii_type == "credit_card":
        digits = re.sub(r"\D", "", compact)
        if len(digits) >= 12:
            return digits[:4] + " **** **** " + digits[-4:]
        return _mask_fallback(compact)

    if pii_type == "voter_id":
        token = re.sub(r"\W", "", compact).upper()
        if len(token) >= 10:
            return token[:3] + "****" + token[-3:]
        return _mask_fallback(compact)

    if pii_type == "dob":
        digits = re.sub(r"\D", "", compact)
        if len(digits) >= 8:
            return "**/**/" + digits[-4:]
        return _mask_fallback(compact)

    return _mask_fallback(compact)


def _build_masked_samples(pii_result, per_type_limit: int = 2) -> dict[str, list[str]]:
    samples: dict[str, list[str]] = {}
    for match in pii_result.matches:
        display_type = DISPLAY_PII_TYPE.get(match.pii_type, match.pii_type.upper())
        masked = _mask_value(match.pii_type, match.value)
        current = samples.setdefault(display_type, [])
        if masked not in current and len(current) < per_type_limit:
            current.append(masked)
    return samples


def _process_results(filename: str, text: str) -> tuple[dict, dict]:
    pii_result = detect_pii(text, use_nlp=True)
    counts = pii_result.counts
    masked_samples = _build_masked_samples(pii_result)
    primary_pii_type, primary_pii_count, _ = select_primary_pii(pii_result.matches)
    if not primary_pii_type:
        primary_pii_type = ""
        primary_pii_count = 0

    csv_row = {
        "filename": filename,
        "status": "success",
        "ocr_char_count": len(text.strip()),
        "primary_pii_type": primary_pii_type,
        "primary_pii_count": primary_pii_count,
        "pii_counts_json": json.dumps(counts, sort_keys=True),
        "pii_samples_json": json.dumps(masked_samples, sort_keys=True),
        "error": "",
    }
    
    pii_list = []
    for match in pii_result.matches:
        display_type = DISPLAY_PII_TYPE.get(match.pii_type, match.pii_type.upper())
        pii_list.append({
            "type": display_type,
            "value": match.value,
            "confidence": round(match.confidence, 4),
            "start": match.start,
            "end": match.end,
            "source": match.source,
        })
        
    json_obj = {
        "filename": filename,
        "status": "success",
        "ocr": {
            "char_count": len(text.strip())
        },
        "pii": pii_list,
        "summary": {
            "counts": counts,
            "primary_type": primary_pii_type
        }
    }
    
    return csv_row, json_obj


def run() -> int:
    repo_root = Path(__file__).resolve().parent.parent
    sample_dir = repo_root / "sample"
    output_dir = sample_dir / "output"
    output_csv = output_dir / "image_scan_report.csv"

    if not sample_dir.exists():
        print(f"[FAIL] sample directory not found: {sample_dir}")
        return 1

    image_files = _discover_images(sample_dir)
    if not image_files:
        print(f"[FAIL] No image files found under {sample_dir}")
        return 1

    parser = ImageParser(lang="en")
    rows: list[dict[str, str | int]] = []
    json_payloads: list[dict] = []

    for image_path in image_files:
        try:
            parsed = parser.parse(str(image_path))
            if not parser.validate(parsed):
                raise ValueError("Invalid parsed structure")

            text_content = parsed["data"][0].get("content", "")
            csv_row, json_obj = _process_results(image_path.name, text_content)
            rows.append(csv_row)
            json_payloads.append(json_obj)
            print(
                f"[OK]  {image_path.name} | chars={csv_row['ocr_char_count']} "
                f"| primary={csv_row['primary_pii_type'] or 'none'}:{csv_row['primary_pii_count']}"
            )
        except Exception as exc:  # noqa: BLE001
            error_row = {
                "filename": image_path.name,
                "status": "error",
                "ocr_char_count": 0,
                "primary_pii_type": "",
                "primary_pii_count": 0,
                "pii_counts_json": "{}",
                "pii_samples_json": "{}",
                "error": str(exc),
            }
            rows.append(error_row)
            json_payloads.append({
                "filename": image_path.name,
                "status": "error",
                "error": str(exc)
            })
            print(f"[ERR] {image_path.name} | {exc}")

    output_dir.mkdir(parents=True, exist_ok=True)
    try:
        with output_csv.open("w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=REPORT_COLUMNS)
            writer.writeheader()
            writer.writerows(rows)
            
        output_json = output_dir / "image_scan_report.json"
        with output_json.open("w", encoding="utf-8") as f:
            json.dump(json_payloads, f, indent=2)
            
    except Exception as exc:  # noqa: BLE001
        print(f"[FAIL] Could not write report: {exc}")
        return 1

    print(f"[OK]  Wrote CSV report: {output_csv}")
    print(f"[OK]  Wrote JSON report: {output_json}")
    print(f"[OK]  Rows: {len(rows)}")
    return 0


if __name__ == "__main__":
    sys.exit(run())
