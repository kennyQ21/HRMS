"""
Router: full multi-format redaction

Endpoints:
  POST /redact          — redact PII from a previously scanned file
  POST /redact-upload   — upload + redact in one step (no prior scan needed)

Redaction types:
  full        → XXXXXXXXXX  (passwords, CVV)
  partial     → XXXX-1234   (credit cards, phones)
  contextual  → [PERSON_NAME] [ADDRESS]   (default, human-readable)
  mask        → ████████████ (PDF visual black box)

Supported formats: PDF, DOCX, XLSX, CSV, Images (JPG/PNG/BMP/TIFF/WEBP)
"""

from __future__ import annotations

import io
import json
import logging
import os
import shutil
import tempfile
import zipfile
from collections import defaultdict
from typing import Optional

from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session

from config import UPLOADS_DIR
from database import get_db
from models import PIILocation
from schemas import RedactRequest
from services.redaction_engine import (
    RedactionEngine,
    REDACT_CONTEXTUAL,
    REDACT_FULL,
    REDACT_PARTIAL,
    REDACT_MASK,
    _detect_format,
)
from services.detection_dispatcher import dispatch_detection
from services.entity_resolution import resolve

logger = logging.getLogger(__name__)
router = APIRouter(tags=["Redaction"])

_engine = RedactionEngine()

IMAGE_EXTENSIONS = (".jpg", ".jpeg", ".png", ".bmp", ".tif", ".tiff", ".webp")


# ── POST /redact — redact from stored scan ────────────────────────────────────

@router.post("/redact")
async def redact_scan(
    body: RedactRequest,
    db: Session = Depends(get_db),
):
    """
    Redact PII from previously scanned and stored files.

    Reads bounding boxes stored during /scan-file for images.
    For PDFs / DOCX / XLSX, retrieves the stored original and applies
    text-based redaction using the resolved entity values.

    Request body (RedactRequest):
        scan_id       — from /scan-file response
        filenames     — which files to redact
        pii_types     — which PII type IDs to redact
        redaction_type — "full" | "partial" | "contextual" | "mask"
    """
    redaction_type = getattr(body, "redaction_type", REDACT_CONTEXTUAL)

    locations = (
        db.query(PIILocation)
        .filter(
            PIILocation.scan_id == body.scan_id,
            PIILocation.source_file.in_(body.filenames),
            PIILocation.pii_type.in_(body.pii_types),
        )
        .all()
    )

    by_file: dict[str, list] = defaultdict(list)
    for loc in locations:
        by_file[loc.source_file].append(loc)

    redacted: dict[str, bytes] = {}
    skipped: list[str] = []

    for filename in body.filenames:
        img_path = UPLOADS_DIR / str(body.scan_id) / filename
        if not img_path.exists():
            logger.warning("Stored file not found: %s", img_path)
            skipped.append(filename)
            continue

        fmt = _detect_format(filename)
        file_locs = by_file.get(filename, [])

        try:
            if fmt == "image" and file_locs:
                # Image: use bbox-based redaction
                redacted[filename] = _redact_image_from_locations(
                    str(img_path), file_locs, filename
                )
            elif fmt in ("pdf", "docx", "xlsx", "csv"):
                # Document: text-based redaction using PIILocation values
                if not file_locs:
                    logger.warning("No PII locations for %s — returning original", filename)
                    with open(str(img_path), "rb") as f:
                        redacted[filename] = f.read()
                    continue
                # Build entity-like objects from PIILocation
                pseudo_entities = _pii_locations_to_entities(file_locs)
                result = _engine.redact(
                    file_path=str(img_path),
                    filename=filename,
                    entities=pseudo_entities,
                    redaction_type=redaction_type,
                    pii_types_filter=set(body.pii_types),
                )
                if result.error:
                    skipped.append(filename)
                else:
                    redacted[filename] = result.redacted_bytes
            else:
                skipped.append(filename)

        except Exception as exc:
            logger.error("Redaction failed for %s: %s", filename, exc)
            skipped.append(filename)

    if not redacted:
        raise HTTPException(
            status_code=404,
            detail="No files could be redacted. Check scan_id, filenames, and pii_types.",
        )

    return _build_redact_response(redacted, skipped, body.scan_id)


# ── POST /redact-upload — upload + redact in one call ────────────────────────

@router.post("/redact-upload")
async def redact_upload(
    file: UploadFile = File(...),
    pii_types: str = Form(None),        # comma-separated list, or None = all
    redaction_type: str = Form(REDACT_CONTEXTUAL),
    realm_name: str = Form(None),
    db: Session = Depends(get_db),
):
    """
    Upload a file, detect PII, and return a redacted version — all in one step.

    Does NOT save a scan record. Use /scan-file for persistent scanning.

    Returns the redacted file directly (with X-PII-Summary header).
    """
    logger.info("redact_upload: filename=%s type=%s", file.filename, redaction_type)

    file_bytes = await file.read()
    pii_filter: Optional[set[str]] = (
        {p.strip() for p in pii_types.split(",")} if pii_types else None
    )

    if redaction_type not in (REDACT_FULL, REDACT_PARTIAL, REDACT_CONTEXTUAL, REDACT_MASK):
        raise HTTPException(
            status_code=400,
            detail=f"Invalid redaction_type. Use: full | partial | contextual | mask",
        )

    # Save to temp file
    suffix = os.path.splitext(file.filename)[1]
    with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as tmp:
        tmp.write(file_bytes)
        temp_path = tmp.name

    try:
        # Parse → detect → redact
        from parsers.unstructured.document_parser import DocumentParser, PDFParser, ImageParser
        from parsers.structured.csv_parser import CSVParser
        from parsers.structured.excel_parser import ExcelParser

        fname_lower = file.filename.lower()
        if fname_lower.endswith((".docx", ".doc", ".odt", ".rtf")):
            from parsers.unstructured.document_parser import DocumentParser
            parser = DocumentParser()
        elif fname_lower.endswith(".pdf"):
            parser = PDFParser()
        elif fname_lower.endswith((".jpg", ".jpeg", ".png", ".bmp", ".tif", ".tiff", ".webp")):
            parser = ImageParser()
        elif fname_lower.endswith(".csv"):
            parser = CSVParser()
        elif fname_lower.endswith((".xlsx", ".xls")):
            parser = ExcelParser()
        else:
            raise HTTPException(status_code=400, detail="Unsupported format for redact-upload")

        parsed = parser.parse(temp_path)
        text = parsed["data"][0].get("content", "") if parsed.get("data") else ""

        if not text.strip():
            raise HTTPException(status_code=422, detail="Could not extract text from file")

        # Detect
        dispatch = dispatch_detection(text, use_nlp=True, use_llm=False)
        resolved = dispatch.resolved
        if pii_filter:
            resolved = [e for e in resolved if e.pii_type in pii_filter]

        if not resolved:
            # Return original if nothing found
            headers = {"X-PII-Summary": "no_pii_detected"}
            return StreamingResponse(
                io.BytesIO(file_bytes),
                media_type="application/octet-stream",
                headers=headers,
            )

        # Redact
        result = _engine.redact(
            file_path=temp_path,
            filename=file.filename,
            entities=resolved,
            redaction_type=redaction_type,
            pii_types_filter=pii_filter,
        )

        pii_summary = json.dumps({
            pii_type: len([e for e in resolved if e.pii_type == pii_type])
            for pii_type in sorted({e.pii_type for e in resolved})
        })

        ext = os.path.splitext(file.filename)[1].lower()
        media_type = _ext_to_mime(ext)

        return StreamingResponse(
            io.BytesIO(result.redacted_bytes),
            media_type=media_type,
            headers={
                "Content-Disposition": f'attachment; filename="redacted_{file.filename}"',
                "X-PII-Summary": pii_summary,
                "X-Entities-Redacted": str(result.entity_count),
            },
        )

    finally:
        if os.path.exists(temp_path):
            os.remove(temp_path)


# ── Helpers ───────────────────────────────────────────────────────────────────

def _redact_image_from_locations(img_path: str, locations: list, filename: str) -> bytes:
    """PIL-based image redaction using stored bbox coordinates."""
    from PIL import Image, ImageDraw

    img  = Image.open(img_path).convert("RGB")
    draw = ImageDraw.Draw(img)

    for loc in locations:
        try:
            poly = json.loads(loc.bbox)
            xs = [p[0] for p in poly]
            ys = [p[1] for p in poly]
            draw.rectangle([min(xs), min(ys), max(xs), max(ys)], fill="black")
        except Exception:
            logger.warning("Malformed bbox for pii_location id=%s", loc.id)

    buf = io.BytesIO()
    ext = img_path.rsplit(".", 1)[-1].lower()
    fmt = "JPEG" if ext in ("jpg", "jpeg") else ext.upper() or "PNG"
    try:
        img.save(buf, format=fmt)
    except Exception:
        img.save(buf, format="PNG")
    buf.seek(0)
    return buf.read()


class _PseudoEntity:
    """Minimal duck-type for RedactionEngine (avoids importing ResolvedEntity)."""
    def __init__(self, pii_type: str, value: str, bbox=None):
        self.pii_type   = pii_type
        self.value      = value
        self.start      = -1
        self.end        = -1
        self.confidence = 1.0
        self.sources    = ["db"]
        self.sensitivity = "High"
        self.metadata   = {"bbox": bbox} if bbox else {}


def _pii_locations_to_entities(locations: list) -> list:
    seen: set[tuple] = set()
    entities: list[_PseudoEntity] = []
    for loc in locations:
        key = (loc.pii_type, loc.value or "")
        if key not in seen:
            seen.add(key)
            bbox = None
            try:
                if loc.bbox:
                    bbox = json.loads(loc.bbox)
            except Exception:
                pass
            entities.append(_PseudoEntity(loc.pii_type, loc.value or "", bbox))
    return entities


def _build_redact_response(
    redacted: dict[str, bytes],
    skipped: list[str],
    scan_id: int,
) -> StreamingResponse:
    """Return single file or ZIP of multiple redacted files."""
    if len(redacted) == 1:
        filename, img_bytes = next(iter(redacted.items()))
        ext = filename.rsplit(".", 1)[-1].lower()
        media_type = _ext_to_mime(f".{ext}")
        headers = {"Content-Disposition": f'attachment; filename="redacted_{filename}"'}
        if skipped:
            headers["X-Redaction-Skipped"] = json.dumps(skipped)
        return StreamingResponse(io.BytesIO(img_bytes), media_type=media_type, headers=headers)

    zip_buf = io.BytesIO()
    with zipfile.ZipFile(zip_buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for filename, data in redacted.items():
            zf.writestr(f"redacted_{filename}", data)
    zip_buf.seek(0)
    headers = {"Content-Disposition": f'attachment; filename="redacted_scan_{scan_id}.zip"'}
    if skipped:
        headers["X-Redaction-Skipped"] = json.dumps(skipped)
    return StreamingResponse(zip_buf, media_type="application/zip", headers=headers)


_MIME_MAP: dict[str, str] = {
    ".pdf":  "application/pdf",
    ".docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    ".xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    ".csv":  "text/csv",
    ".jpg":  "image/jpeg", ".jpeg": "image/jpeg",
    ".png":  "image/png",
    ".bmp":  "image/bmp",
    ".tif":  "image/tiff", ".tiff": "image/tiff",
    ".webp": "image/webp",
}


def _ext_to_mime(ext: str) -> str:
    return _MIME_MAP.get(ext.lower(), "application/octet-stream")
