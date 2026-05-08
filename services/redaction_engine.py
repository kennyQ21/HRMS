"""
services/redaction_engine.py
------------------------------
Full Multi-Format Redaction Engine.

Supports all document types with format-appropriate redaction:

  ┌──────────┬──────────────────────────────────────────────────┐
  │ Format   │ Method                                           │
  ├──────────┼──────────────────────────────────────────────────┤
  │ PDF      │ PyMuPDF — black rectangle overlay on text spans  │
  │ DOCX     │ python-docx — inline text replacement in runs    │
  │ XLSX     │ openpyxl — cell value masking                    │
  │ Image    │ PIL — black rectangle over bbox regions          │
  │ CSV      │ pandas — column-level cell masking               │
  │ Plain    │ string replacement                               │
  └──────────┴──────────────────────────────────────────────────┘

Redaction Types:
  • FULL        → XXXXXXXXXXXX  (passwords, CVV)
  • PARTIAL     → XXXX-XXXX-1234  (credit cards, phones)
  • CONTEXTUAL  → [PERSON_NAME]  [ADDRESS]  (documents, readable output)
  • MASK_CHAR   → ████████████  (visual PDF overlay)

Usage:
    engine = RedactionEngine()
    result = engine.redact(
        file_path="/tmp/doc.pdf",
        filename="doc.pdf",
        entities=resolved_entities,
        redaction_type="contextual",
    )
    # result.redacted_bytes  — file bytes ready to return / save
    # result.redaction_map   — {entity_value: redacted_value}
"""

from __future__ import annotations

import io
import logging
import re
import tempfile
import os
from dataclasses import dataclass, field
from typing import Optional

logger = logging.getLogger(__name__)

# ── Redaction type constants ──────────────────────────────────────────────────

REDACT_FULL        = "full"         # XXXXXXXXXXXX
REDACT_PARTIAL     = "partial"      # XXXX-XXXX-1234
REDACT_CONTEXTUAL  = "contextual"   # [PERSON_NAME]
REDACT_MASK        = "mask"         # ████████████ (PDF visual)

# PII types that get FULL redaction by default
_FULL_REDACT_TYPES: set[str] = {
    "password", "cvv", "ssn",
}

# PII types that get PARTIAL masking (show last N chars)
_PARTIAL_REDACT_TYPES: dict[str, int] = {
    "credit_card":  4,    # show last 4
    "bank_account": 4,
    "aadhaar":      4,
    "phone":        4,
    "pan":          0,    # show none — PAN is 10 chars, FULL is safer
}

# Contextual label map for [TYPE] replacement
_CONTEXTUAL_LABELS: dict[str, str] = {
    "name":                    "[PERSON_NAME]",
    "address":                 "[ADDRESS]",
    "email":                   "[EMAIL]",
    "corporate_email":         "[CORPORATE_EMAIL]",
    "phone":                   "[PHONE_NUMBER]",
    "dob":                     "[DATE_OF_BIRTH]",
    "aadhaar":                 "[AADHAAR_NUMBER]",
    "pan":                     "[PAN_NUMBER]",
    "passport":                "[PASSPORT_NUMBER]",
    "voter_id":                "[VOTER_ID]",
    "driving_license":         "[DL_NUMBER]",
    "ssn":                     "[SSN]",
    "credit_card":             "[CARD_NUMBER]",
    "bank_account":            "[ACCOUNT_NUMBER]",
    "upi":                     "[UPI_ID]",
    "ifsc":                    "[IFSC_CODE]",
    "cvv":                     "[CVV]",
    "expiry":                  "[EXPIRY_DATE]",
    "password":                "[PASSWORD]",
    "user_id":                 "[USER_ID]",
    "organization":            "[ORGANIZATION]",
    "occupation":              "[OCCUPATION]",
    "employee_id":             "[EMPLOYEE_ID]",
    "diagnosis":               "[MEDICAL_DIAGNOSIS]",
    "allergies":               "[ALLERGY_RECORD]",
    "treatment_history":       "[TREATMENT_HISTORY]",
    "prescription":            "[PRESCRIPTION]",
    "immunization":            "[IMMUNIZATION_RECORD]",
    "blood_group":             "[BLOOD_GROUP]",
    "mrn":                     "[MEDICAL_RECORD_NUMBER]",
    "insurance_policy":        "[INSURANCE_POLICY]",
    "insurance_provider":      "[INSURANCE_PROVIDER]",
    "educational_qualification":"[QUALIFICATION]",
    "city":                    "[CITY]",
    "pincode":                 "[PINCODE]",
    "ip_address":              "[IP_ADDRESS]",
    "nationality":             "[NATIONALITY]",
    "gender":                  "[GENDER]",
    "age":                     "[AGE]",
    "marital_status":          "[MARITAL_STATUS]",
}


@dataclass
class RedactionResult:
    """Output of one redact() call."""
    filename:       str
    format:         str                         # pdf | docx | xlsx | image | csv | text
    redacted_bytes: bytes = b""
    redaction_map:  dict  = field(default_factory=dict)  # original → replacement
    entity_count:   int   = 0
    error:          Optional[str] = None


class RedactionEngine:

    def redact(
        self,
        file_path: str,
        filename: str,
        entities: list,                     # list[ResolvedEntity]
        redaction_type: str = REDACT_CONTEXTUAL,
        pii_types_filter: Optional[set[str]] = None,
    ) -> RedactionResult:
        """
        Apply redaction to a file for all resolved entities.

        Args:
            file_path:        Path to the source file.
            filename:         Original filename (used for format detection).
            entities:         Resolved entities from entity_resolution.resolve().
            redaction_type:   "full" | "partial" | "contextual" | "mask"
            pii_types_filter: Only redact these PII type IDs (None = all).
        """
        if pii_types_filter:
            entities = [e for e in entities if e.pii_type in pii_types_filter]

        if not entities:
            with open(file_path, "rb") as f:
                return RedactionResult(
                    filename=filename, format=_detect_format(filename),
                    redacted_bytes=f.read(), entity_count=0,
                )

        fmt = _detect_format(filename)
        redaction_map = self._build_redaction_map(entities, redaction_type)

        logger.info(
            "[REDACTION] %s format=%s entities=%d type=%s",
            filename, fmt, len(entities), redaction_type,
        )

        try:
            if fmt == "pdf":
                result_bytes = self._redact_pdf(file_path, entities, redaction_map, redaction_type)
            elif fmt == "docx":
                result_bytes = self._redact_docx(file_path, redaction_map)
            elif fmt == "xlsx":
                result_bytes = self._redact_xlsx(file_path, redaction_map)
            elif fmt == "image":
                result_bytes = self._redact_image(file_path, entities, filename)
            elif fmt == "csv":
                result_bytes = self._redact_csv(file_path, redaction_map)
            else:
                result_bytes = self._redact_text(file_path, redaction_map)

            return RedactionResult(
                filename=filename,
                format=fmt,
                redacted_bytes=result_bytes,
                redaction_map=redaction_map,
                entity_count=len(entities),
            )

        except Exception as exc:
            logger.error("[REDACTION] Failed for %s: %s", filename, exc, exc_info=True)
            with open(file_path, "rb") as f:
                return RedactionResult(
                    filename=filename, format=fmt,
                    redacted_bytes=f.read(),
                    entity_count=0,
                    error=str(exc),
                )

    # ── Redaction map builder ─────────────────────────────────────────────────

    def _build_redaction_map(self, entities: list, redaction_type: str) -> dict[str, str]:
        """Build {original_value: replacement} map for text-based redaction."""
        rmap: dict[str, str] = {}
        for e in entities:
            val = e.value
            if not val:
                continue
            rmap[val] = self._get_replacement(val, e.pii_type, redaction_type)
        return rmap

    def _get_replacement(
        self, value: str, pii_type: str, redaction_type: str
    ) -> str:
        """Choose the right replacement string for a given PII value."""
        # Per-type overrides take priority over the global redaction_type
        if pii_type in _FULL_REDACT_TYPES:
            return "X" * len(value)

        if redaction_type == REDACT_CONTEXTUAL:
            return _CONTEXTUAL_LABELS.get(pii_type, f"[{pii_type.upper()}]")

        if redaction_type == REDACT_PARTIAL or pii_type in _PARTIAL_REDACT_TYPES:
            keep = _PARTIAL_REDACT_TYPES.get(pii_type, 4)
            digits = re.sub(r"\D", "", value)
            if keep > 0 and len(digits) > keep:
                masked = "X" * (len(digits) - keep) + digits[-keep:]
                return masked
            return "X" * len(value)

        if redaction_type == REDACT_FULL:
            return "X" * len(value)

        # Default
        return _CONTEXTUAL_LABELS.get(pii_type, f"[{pii_type.upper()}]")

    # ── PDF redaction (PyMuPDF) ───────────────────────────────────────────────

    def _redact_pdf(
        self,
        file_path: str,
        entities: list,
        redaction_map: dict,
        redaction_type: str,
    ) -> bytes:
        import fitz  # PyMuPDF

        doc = fitz.open(file_path)

        for page in doc:
            for entity in entities:
                val = entity.value
                if not val or len(val) < 2:
                    continue
                # Search for all occurrences of the value on this page
                instances = page.search_for(val, quads=False)
                for rect in instances:
                    # Draw filled black rectangle over the text
                    if redaction_type == REDACT_MASK:
                        page.add_redact_annot(rect, fill=(0, 0, 0))
                    else:
                        replacement = redaction_map.get(val, f"[{entity.pii_type.upper()}]")
                        page.add_redact_annot(
                            rect,
                            text=replacement,
                            fill=(0, 0, 0),
                            text_color=(1, 1, 1),
                            fontsize=8,
                        )
            # Apply all redaction annotations on this page
            page.apply_redactions()

        buf = io.BytesIO()
        doc.save(buf)
        doc.close()
        buf.seek(0)
        logger.info("[REDACTION] PDF: %d pages processed", len(doc))
        return buf.read()

    # ── DOCX redaction (python-docx) ──────────────────────────────────────────

    def _redact_docx(self, file_path: str, redaction_map: dict) -> bytes:
        import docx

        doc = docx.Document(file_path)

        def _replace_in_run(run, rmap: dict) -> None:
            text = run.text
            for original, replacement in rmap.items():
                if original in text:
                    text = text.replace(original, replacement)
            run.text = text

        # Process paragraphs
        for para in doc.paragraphs:
            for run in para.runs:
                _replace_in_run(run, redaction_map)

        # Process tables
        for table in doc.tables:
            for row in table.rows:
                for cell in row.cells:
                    for para in cell.paragraphs:
                        for run in para.runs:
                            _replace_in_run(run, redaction_map)

        buf = io.BytesIO()
        doc.save(buf)
        buf.seek(0)
        logger.info("[REDACTION] DOCX: processed %d paragraphs", len(doc.paragraphs))
        return buf.read()

    # ── XLSX redaction (openpyxl) ─────────────────────────────────────────────

    def _redact_xlsx(self, file_path: str, redaction_map: dict) -> bytes:
        from openpyxl import load_workbook

        wb = load_workbook(file_path)
        cells_redacted = 0

        for ws in wb.worksheets:
            for row in ws.iter_rows():
                for cell in row:
                    if cell.value is None:
                        continue
                    cell_str = str(cell.value)
                    changed = False
                    for original, replacement in redaction_map.items():
                        if original in cell_str:
                            cell_str = cell_str.replace(original, replacement)
                            changed = True
                    if changed:
                        cell.value = cell_str
                        cells_redacted += 1

        buf = io.BytesIO()
        wb.save(buf)
        buf.seek(0)
        logger.info("[REDACTION] XLSX: %d cells redacted", cells_redacted)
        return buf.read()

    # ── Image redaction (PIL + bbox) ──────────────────────────────────────────

    def _redact_image(
        self, file_path: str, entities: list, filename: str
    ) -> bytes:
        from PIL import Image, ImageDraw

        img   = Image.open(file_path).convert("RGB")
        draw  = ImageDraw.Draw(img)
        count = 0

        for entity in entities:
            bbox = entity.metadata.get("bbox")
            if not bbox:
                continue
            try:
                xs = [p[0] for p in bbox]
                ys = [p[1] for p in bbox]
                draw.rectangle([min(xs), min(ys), max(xs), max(ys)], fill="black")
                count += 1
            except Exception as exc:
                logger.warning("[REDACTION] Image bbox error: %s", exc)

        buf = io.BytesIO()
        ext = os.path.splitext(filename)[1].lower().lstrip(".")
        fmt = "JPEG" if ext in ("jpg", "jpeg") else ext.upper() or "PNG"
        try:
            img.save(buf, format=fmt)
        except Exception:
            img.save(buf, format="PNG")
        buf.seek(0)
        logger.info("[REDACTION] Image: %d regions redacted", count)
        return buf.read()

    # ── CSV redaction ─────────────────────────────────────────────────────────

    def _redact_csv(self, file_path: str, redaction_map: dict) -> bytes:
        with open(file_path, "r", errors="replace") as f:
            content = f.read()
        for original, replacement in redaction_map.items():
            content = content.replace(original, replacement)
        return content.encode("utf-8")

    # ── Plain text fallback ───────────────────────────────────────────────────

    def _redact_text(self, file_path: str, redaction_map: dict) -> bytes:
        with open(file_path, "r", errors="replace") as f:
            content = f.read()
        for original, replacement in sorted(
            redaction_map.items(), key=lambda kv: -len(kv[0])
        ):
            content = content.replace(original, replacement)
        return content.encode("utf-8")


# ── Helpers ───────────────────────────────────────────────────────────────────

_FORMAT_MAP: dict[str, str] = {
    ".pdf":  "pdf",
    ".docx": "docx", ".doc": "docx",
    ".xlsx": "xlsx", ".xls": "xlsx",
    ".csv":  "csv",
    ".jpg":  "image", ".jpeg": "image",
    ".png":  "image", ".bmp": "image",
    ".tif":  "image", ".tiff": "image", ".webp": "image",
}


def _detect_format(filename: str) -> str:
    ext = os.path.splitext(filename.lower())[1]
    return _FORMAT_MAP.get(ext, "text")


# ── Module-level singleton ────────────────────────────────────────────────────

_redaction_engine = RedactionEngine()


def redact_document(
    file_path: str,
    filename: str,
    entities: list,
    redaction_type: str = REDACT_CONTEXTUAL,
    pii_types_filter: Optional[set[str]] = None,
) -> RedactionResult:
    return _redaction_engine.redact(
        file_path=file_path,
        filename=filename,
        entities=entities,
        redaction_type=redaction_type,
        pii_types_filter=pii_types_filter,
    )
