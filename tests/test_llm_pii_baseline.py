#!/usr/bin/env python3
"""
LLM-only PII baseline evaluator (Qwen via llama.cpp OpenAI-compatible API).

Purpose:
    Compare pure LLM extraction against the current deterministic pipeline.

Outputs:
    - sample/output/llm_only_pii_report.json
    - sample/output/llm_only_pii_summary.csv

Notes:
    - Stores masked samples only (no raw PII in output files).
    - Expects llama-server running locally (default: http://localhost:8080/v1).
"""

from __future__ import annotations

import argparse
import csv
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional

import requests
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from parsers.unstructured.document_parser import DocumentParser, ImageParser, PDFParser
from services.pii_service import detect_pii

IMAGE_EXTENSIONS = {".jpg", ".jpeg", ".png", ".bmp", ".tif", ".tiff", ".webp"}
STRUCTURED_TYPES = {"pan", "aadhaar", "phone", "email", "credit_card", "voter_id"}

TYPE_ALIASES = {
    "PAN": "pan",
    "IN_PAN": "pan",
    "AADHAAR": "aadhaar",
    "AADHAR": "aadhaar",
    "IN_AADHAAR": "aadhaar",
    "PHONE": "phone",
    "PHONE_NUMBER": "phone",
    "EMAIL": "email",
    "PERSON": "name",
    "NAME": "name",
    "ORG": "organization",
    "ORGANIZATION": "organization",
    "ADDRESS": "address",
    "LOCATION": "address",
    "VOTER_ID": "voter_id",
    "IN_VOTER": "voter_id",
    "CREDIT_CARD": "credit_card",
}

DISPLAY_TYPE = {
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

ENTITY_PROMPT = """Extract all PII from the text.

Return STRICT JSON only:
{{
  "entities": [
    {{
      "type": "PAN | AADHAAR | NAME | ADDRESS | PHONE | EMAIL | VOTER_ID | CREDIT_CARD",
      "value": "exact text"
    }}
  ]
}}

Rules:
- Do NOT hallucinate
- Only return values present in text
- Keep exact formatting

Text:
{text}
"""


@dataclass
class InputDoc:
    path: Path
    kind: str
    text: str


def _normalize_spaces(value: str) -> str:
    return re.sub(r"\s+", " ", value).strip()


def _mask_fallback(value: str) -> str:
    compact = _normalize_spaces(value)
    if len(compact) <= 2:
        return "***"
    return compact[:2] + "***"


def _mask_value(pii_type: str, value: str) -> str:
    compact = _normalize_spaces(value)
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
        return f"{local[:2]}***@{domain}"

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

    return _mask_fallback(compact)


def _extract_text(path: Path, parsers: dict[str, Any]) -> InputDoc:
    suffix = path.suffix.lower()
    if suffix in IMAGE_EXTENSIONS:
        parser = parsers["image"]
        parsed = parser.parse(str(path))
        return InputDoc(path=path, kind="image", text=parsed["data"][0].get("content", ""))
    if suffix == ".pdf":
        parser = parsers["pdf"]
        parsed = parser.parse(str(path))
        return InputDoc(path=path, kind="pdf", text=parsed["data"][0].get("content", ""))
    if suffix in {".docx", ".doc", ".odt", ".rtf"}:
        parser = parsers["document"]
        parsed = parser.parse(str(path))
        return InputDoc(path=path, kind="document", text=parsed["data"][0].get("content", ""))
    raise ValueError(f"Unsupported file type: {path.name}")


def _extract_json_block(text: str) -> dict[str, Any]:
    content = text.strip()
    if not content:
        return {"entities": []}

    try:
        return json.loads(content)
    except json.JSONDecodeError:
        pass

    match = re.search(r"\{.*\}", content, flags=re.S)
    if not match:
        raise ValueError("No JSON object found in LLM response.")
    return json.loads(match.group(0))


def _normalize_entity_type(raw_type: str) -> Optional[str]:
    if not raw_type:
        return None
    token = re.sub(r"[\s\-]+", "_", raw_type.strip().upper())
    return TYPE_ALIASES.get(token)


def _validate_structured(pii_type: str, value: str) -> bool:
    if pii_type == "pan":
        return bool(re.fullmatch(r"[A-Z]{5}\d{4}[A-Z]", re.sub(r"\W", "", value).upper()))
    if pii_type == "aadhaar":
        return len(re.sub(r"\D", "", value)) == 12
    if pii_type == "phone":
        digits = re.sub(r"\D", "", value)
        return len(digits) in {10, 12}
    if pii_type == "email":
        return bool(re.fullmatch(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", value.strip()))
    if pii_type == "voter_id":
        return bool(re.fullmatch(r"[A-Z]{3}\d{7}", re.sub(r"\W", "", value).upper()))
    return True


def _contains_in_text(text: str, value: str) -> bool:
    if not value:
        return False
    if value in text:
        return True
    text_norm = _normalize_spaces(text).lower()
    value_norm = _normalize_spaces(value).lower()
    return value_norm in text_norm


def _build_pipeline_value_sets(text: str) -> dict[str, set[str]]:
    result = detect_pii(text, use_nlp=True)
    out: dict[str, set[str]] = {}
    for match in result.matches:
        if match.pii_type not in STRUCTURED_TYPES:
            continue
        normalized = re.sub(r"\W+", "", match.value).lower()
        if normalized:
            out.setdefault(match.pii_type, set()).add(normalized)
    return out


def _build_current_csv_counts(path: Path) -> dict[str, dict[str, int]]:
    if not path.exists():
        return {}
    rows = list(csv.DictReader(path.open(encoding="utf-8")))
    output: dict[str, dict[str, int]] = {}
    for row in rows:
        filename = row.get("filename", "")
        if not filename:
            continue
        try:
            output[filename] = json.loads(row.get("pii_counts_json", "{}"))
        except json.JSONDecodeError:
            output[filename] = {}
    return output


def _call_llm(
    api_base: str,
    model: str,
    text: str,
    temperature: float,
    timeout: int,
) -> str:
    url = api_base.rstrip("/") + "/chat/completions"
    payload = {
        "model": model,
        "temperature": temperature,
        "top_p": 0.9,
        "messages": [
            {"role": "system", "content": "You are a strict JSON extraction engine."},
            {"role": "user", "content": ENTITY_PROMPT.format(text=text)},
        ],
    }
    response = requests.post(url, json=payload, timeout=timeout)
    response.raise_for_status()
    body = response.json()
    return body["choices"][0]["message"]["content"]


def _check_server(api_base: str, timeout: int) -> None:
    url = api_base.rstrip("/") + "/models"
    response = requests.get(url, timeout=min(timeout, 10))
    response.raise_for_status()


def _find_inputs(sample_dir: Path, include_pdf: Path, include_docx: Optional[Path]) -> list[Path]:
    paths: list[Path] = sorted(
        p for p in sample_dir.iterdir()
        if p.is_file() and p.suffix.lower() in IMAGE_EXTENSIONS
    )
    if include_pdf.exists():
        paths.append(include_pdf)
    if include_docx and include_docx.exists():
        paths.append(include_docx)
    return paths


def main() -> int:
    parser = argparse.ArgumentParser(description="LLM-only PII baseline evaluator.")
    parser.add_argument("--api-base", default="http://localhost:8080/v1")
    parser.add_argument("--model", default="qwen")
    parser.add_argument("--temperature", type=float, default=0.2)
    parser.add_argument("--timeout", type=int, default=120)
    parser.add_argument("--sample-dir", default="sample")
    parser.add_argument("--pdf", default="Scanned-receipt-example-file.pdf")
    parser.add_argument("--docx", default="")
    parser.add_argument("--current-csv", default="sample/output/image_scan_report.csv")
    parser.add_argument("--output-json", default="sample/output/llm_only_pii_report.json")
    parser.add_argument("--output-csv", default="sample/output/llm_only_pii_summary.csv")
    args = parser.parse_args()

    root = Path(__file__).resolve().parent.parent
    sample_dir = (root / args.sample_dir).resolve()
    pdf_path = (root / args.pdf).resolve()
    docx_path = (root / args.docx).resolve() if args.docx else None
    current_csv = (root / args.current_csv).resolve()
    output_json = (root / args.output_json).resolve()
    output_csv = (root / args.output_csv).resolve()

    input_paths = _find_inputs(sample_dir, pdf_path, docx_path)
    if not input_paths:
        print("[FAIL] No input files found (images/pdf/docx).")
        return 1
    try:
        _check_server(args.api_base, args.timeout)
    except Exception as exc:  # noqa: BLE001
        print(f"[FAIL] llama-server not reachable at {args.api_base}: {exc}")
        print("       Start server first, e.g. ./llama-server --model <model.gguf> --port 8080")
        return 1

    current_counts = _build_current_csv_counts(current_csv)
    output_json.parent.mkdir(parents=True, exist_ok=True)

    report_rows: list[dict[str, Any]] = []
    summary_rows: list[dict[str, Any]] = []
    success_count = 0
    parser_cache = {
        "image": ImageParser(lang="en"),
        "pdf": PDFParser(lang="en"),
        "document": DocumentParser(),
    }

    for path in input_paths:
        print(f"[INFO] Processing {path.name}")
        try:
            doc = _extract_text(path, parser_cache)
            content = doc.text or ""
            llm_raw = _call_llm(
                api_base=args.api_base,
                model=args.model,
                text=content,
                temperature=args.temperature,
                timeout=args.timeout,
            )
            parsed = _extract_json_block(llm_raw)
            raw_entities = parsed.get("entities", []) if isinstance(parsed, dict) else []

            normalized_entities: list[dict[str, str]] = []
            hallucinations: list[dict[str, str]] = []
            format_errors: list[dict[str, str]] = []
            samples: dict[str, list[str]] = {}
            llm_value_sets: dict[str, set[str]] = {}

            for entity in raw_entities:
                if not isinstance(entity, dict):
                    continue
                pii_type = _normalize_entity_type(str(entity.get("type", "")))
                value = _normalize_spaces(str(entity.get("value", "")))
                if not pii_type or not value:
                    continue

                normalized_entities.append({"type": pii_type, "value": value})

                display_type = DISPLAY_TYPE.get(pii_type, pii_type.upper())
                masked = _mask_value(pii_type, value)
                current = samples.setdefault(display_type, [])
                if masked not in current and len(current) < 2:
                    current.append(masked)

                if not _contains_in_text(content, value):
                    hallucinations.append({"type": pii_type, "value": _mask_value(pii_type, value)})

                if pii_type in STRUCTURED_TYPES and not _validate_structured(pii_type, value):
                    format_errors.append({"type": pii_type, "value": _mask_value(pii_type, value)})

                if pii_type in STRUCTURED_TYPES:
                    llm_value_sets.setdefault(pii_type, set()).add(re.sub(r"\W+", "", value).lower())

            pipeline_structured = _build_pipeline_value_sets(content)
            missing_vs_pipeline: dict[str, list[str]] = {}
            for pii_type, expected_set in pipeline_structured.items():
                missing = sorted(v for v in expected_set if v not in llm_value_sets.get(pii_type, set()))
                if missing:
                    missing_vs_pipeline[pii_type] = [_mask_value(pii_type, v) for v in missing]

            llm_counts: dict[str, int] = {}
            for entity in normalized_entities:
                llm_counts[entity["type"]] = llm_counts.get(entity["type"], 0) + 1

            current_file_counts = current_counts.get(path.name, {})
            missing_types_vs_current = sorted(
                key for key, count in current_file_counts.items()
                if count > 0 and llm_counts.get(key, 0) == 0
            )

            report_rows.append(
                {
                    "filename": path.name,
                    "source_type": doc.kind,
                    "ocr_char_count": len(content.strip()),
                    "llm_entity_count": len(normalized_entities),
                    "llm_counts": llm_counts,
                    "primary_pii_type": max(llm_counts, key=llm_counts.get) if llm_counts else "",
                    "samples_masked": samples,
                    "hallucinations_masked": hallucinations,
                    "format_errors_masked": format_errors,
                    "missing_structured_vs_pipeline_masked": missing_vs_pipeline,
                    "missing_types_vs_current_csv": missing_types_vs_current,
                }
            )

            summary_rows.append(
                {
                    "filename": path.name,
                    "source_type": doc.kind,
                    "status": "success",
                    "ocr_char_count": len(content.strip()),
                    "llm_entity_count": len(normalized_entities),
                    "hallucination_count": len(hallucinations),
                    "format_error_count": len(format_errors),
                    "missing_structured_count": sum(len(v) for v in missing_vs_pipeline.values()),
                    "missing_types_vs_current_csv": ";".join(missing_types_vs_current),
                    "primary_pii_type": max(llm_counts, key=llm_counts.get) if llm_counts else "",
                }
            )
            success_count += 1
        except Exception as exc:  # noqa: BLE001
            report_rows.append(
                {
                    "filename": path.name,
                    "source_type": path.suffix.lower().lstrip("."),
                    "status": "error",
                    "error": str(exc),
                }
            )
            summary_rows.append(
                {
                    "filename": path.name,
                    "source_type": path.suffix.lower().lstrip("."),
                    "status": "error",
                    "ocr_char_count": 0,
                    "llm_entity_count": 0,
                    "hallucination_count": 0,
                    "format_error_count": 0,
                    "missing_structured_count": 0,
                    "missing_types_vs_current_csv": "",
                    "primary_pii_type": "",
                }
            )

    output_json.write_text(json.dumps(report_rows, indent=2), encoding="utf-8")
    with output_csv.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=[
                "filename",
                "source_type",
                "status",
                "ocr_char_count",
                "llm_entity_count",
                "hallucination_count",
                "format_error_count",
                "missing_structured_count",
                "missing_types_vs_current_csv",
                "primary_pii_type",
            ],
        )
        writer.writeheader()
        writer.writerows(summary_rows)

    print(f"[OK] Wrote: {output_json}")
    print(f"[OK] Wrote: {output_csv}")
    if success_count == 0:
        print("[FAIL] LLM extraction failed for all inputs.")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
