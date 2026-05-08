"""
Router: file PII scanning — full hybrid pipeline

POST /scan-file
  Upload a file (or ZIP archive), run it through the complete pipeline:

  IngestionDispatcher → FileParser + OCR → ContentReconstruction →
  TextNormalization → DetectionDispatcher → EntityResolution →
  PIIClassification → Validator → UnifiedJSONOutput

Supported formats: CSV, XLSX, PDF, DOCX, DOC, ODT, RTF, SQL, MDB,
                   Images (JPG/PNG/BMP/TIFF/WEBP), ZIP archives.
"""

from __future__ import annotations

import logging
import os
import shutil
import tempfile
import time
import zipfile
from datetime import datetime
from typing import Optional

import PyPDF2
from fastapi import APIRouter, Depends, File, Form, UploadFile
from fastapi.concurrency import run_in_threadpool
from sqlalchemy.orm import Session

from config import UPLOADS_DIR
from constants import PII_TYPES
from database import get_db
from models import ColumnScan, Scan, ScanAnomaly
from parsers.structured.csv_parser import CSVParser
from parsers.structured.excel_parser import ExcelParser
from parsers.unstructured.access_parser import MDBParser
from parsers.unstructured.document_parser import DocumentParser, ImageParser, PDFParser
from parsers.unstructured.sql_parser import SQLParser

from services.ingestion_dispatcher import dispatch_ingestion, IngestionPlan
from services.content_reconstruction import reconstruct_content
from services.detection_dispatcher import dispatch_detection
from services.entity_resolution import resolve, resolved_to_pii_counts, select_primary_from_resolved
from services.validator import validate_results
from services.output_schema import build_scan_response, build_error_response
from services.pipeline_manager import get_pipeline

logger = logging.getLogger(__name__)
router = APIRouter(tags=["File Scanning"])

IMAGE_EXTENSIONS = (".jpg", ".jpeg", ".png", ".bmp", ".tif", ".tiff", ".webp")


# ── Parser factory ────────────────────────────────────────────────────────────

def _get_parser(filename: str, password: Optional[str] = None):
    fn = filename.lower()
    if fn.endswith((".xlsx", ".xls")):   return ExcelParser()
    if fn.endswith(".csv"):              return CSVParser()
    if fn.endswith((".docx", ".doc", ".odt", ".rtf")): return DocumentParser()
    if fn.endswith(".pdf"):              return PDFParser(password=password)
    if fn.endswith(IMAGE_EXTENSIONS):   return ImageParser()
    if fn.endswith(".mdb"):             return MDBParser()
    if fn.endswith(".sql"):             return SQLParser()
    return None


def _check_pdf_protected(path: str) -> bool:
    try:
        with open(path, "rb") as f:
            return PyPDF2.PdfReader(f).is_encrypted
    except Exception:
        return False


def _save_image_for_redaction(src: str, scan_id: int, filename: str) -> None:
    dest = UPLOADS_DIR / str(scan_id)
    dest.mkdir(parents=True, exist_ok=True)
    shutil.copy2(src, dest / os.path.basename(filename))


# ── Persist scan to DB ────────────────────────────────────────────────────────

def _persist_scan(
    db: Session,
    scan: Scan,
    filename: str,
    resolved_entities: list,
    pii_types: list,
) -> None:
    """
    Store resolved entities into column_scans + scan_anomalies so
    /get-scan-results continues to work unchanged.
    """
    selected_ids = {p["id"] for p in pii_types}
    filtered = [e for e in resolved_entities if e.pii_type in selected_ids]

    counts = resolved_to_pii_counts(filtered)
    primary_type, primary_count, _ = select_primary_from_resolved(filtered, selected_ids)

    col_scan = ColumnScan(
        db_name=filename,
        table_name="document",
        column_name="content",
        total_rows=1,
        primary_pii_type=primary_type,
        primary_pii_match_count=primary_count or 0,
        scan=scan,
    )
    db.add(col_scan)
    db.flush()

    for pii_id, count in counts.items():
        if pii_id != primary_type and count > 0:
            db.add(ScanAnomaly(
                pii_type=pii_id,
                match_count=count,
                confidence_score=round(
                    sum(e.confidence for e in filtered if e.pii_type == pii_id) / count, 4
                ),
                column_scan=col_scan,
            ))


# ── Core pipeline (blocking) ──────────────────────────────────────────────────

def _run_pipeline(
    temp_path: str,
    filename: str,
    db: Session,
    scan: Scan,
    password: Optional[str],
    realm_name: Optional[str],
) -> dict:
    """
    Run the full pipeline for one file.  Returns the unified JSON dict.
    """
    t0 = time.perf_counter()

    pipeline = get_pipeline()

    with pipeline.begin("scan-file", source=filename) as ctx:

        # ── 1. Ingestion Dispatcher ───────────────────────────────────────────
        plan: IngestionPlan = dispatch_ingestion(temp_path, filename, password)

        if plan.parser_type == "unknown":
            return build_error_response(filename, "Unsupported file format")

        # ── 2. File Parser ────────────────────────────────────────────────────
        parser = _get_parser(filename, password)
        if parser is None:
            return build_error_response(filename, "No parser available for this format")

        is_image = filename.lower().endswith(IMAGE_EXTENSIONS)
        if is_image:
            parsed_data = parser.parse_with_boxes(temp_path)
            ocr_output = [{
                "text": parsed_data["data"][0].get("content", ""),
                "lines": parsed_data.get("lines", []),
            }]
        else:
            parsed_data = parser.parse(temp_path)
            ocr_output = None

        if not parser.validate(parsed_data):
            return build_error_response(filename, "Invalid file structure")

        # ── 3. Content Reconstruction ─────────────────────────────────────────
        content_doc = reconstruct_content(
            filename=filename,
            parser_output=parsed_data,
            ocr_output=ocr_output,
            file_metadata={"doc_type": plan.doc_type},
        )

        # ── 4. Text Normalization (inside detection_dispatcher) ───────────────
        # The DetectionDispatcher handles normalisation internally.

        working_text = content_doc.full_text
        if not working_text.strip():
            working_text = parsed_data["data"][0].get("content", "") if parsed_data.get("data") else ""

        # ── 5. Detection Dispatcher ───────────────────────────────────────────
        dispatch_result = dispatch_detection(
            text=working_text,
            use_nlp=True,
            use_llm=False,      # LLM off by default — enable per doc_type if needed
            use_otter=True,
            doc_type=plan.doc_type,
        )

        # ── 6. Entity Resolution (inside dispatcher) ──────────────────────────
        resolved = dispatch_result.resolved
        engine_results = dispatch_result.engine_results

        ctx.record_engines(engine_results)

        # ── 7. PII Classification (in constants + entity_resolution) ─────────
        # Already done — each ResolvedEntity has .sensitivity

        # ── 8. Persist to DB ──────────────────────────────────────────────────
        _persist_scan(db, scan, filename, resolved, PII_TYPES)

        # Save image for later redaction
        if is_image:
            _save_image_for_redaction(temp_path, scan.id, filename)

        # ── 9. Validation Layer ───────────────────────────────────────────────
        validation = validate_results(
            text=working_text,
            resolved_entities=resolved,
        )

        # ── 10. Build unified output ──────────────────────────────────────────
        elapsed_ms = (time.perf_counter() - t0) * 1000

        return build_scan_response(
            scan_id=scan.id,
            filename=filename,
            resolved_entities=resolved,
            engine_results=engine_results,
            content_doc=content_doc,
            ingestion_plan=plan,
            validation_report=validation,
            redaction_map=None,
            elapsed_ms=elapsed_ms,
        )


# ── /scan-file (blocking wrapper) ────────────────────────────────────────────

def _scan_file_blocking(
    file_bytes: bytes,
    original_filename: str,
    realm_name: Optional[str],
    password: Optional[str],
    db: Session,
) -> dict:
    all_results = []
    temp_path = None

    try:
        suffix = os.path.splitext(original_filename)[1]
        with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as tmp:
            tmp.write(file_bytes)
            temp_path = tmp.name

        scan = Scan(
            name=f"File_Scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
            connector_id="file_upload",
            realm_name=realm_name,
        )
        db.add(scan)
        db.flush()

        filename_lower = original_filename.lower()

        # ── ZIP handling ──────────────────────────────────────────────────────
        if filename_lower.endswith(".zip"):
            extract_dir = tempfile.mkdtemp(prefix="zip_extract_")
            try:
                with zipfile.ZipFile(temp_path, "r") as zf:
                    is_encrypted = any(zi.flag_bits & 0x1 for zi in zf.filelist)
                    if is_encrypted and not password:
                        return {"status": "error",
                                "message": "ZIP is password-protected. Please provide a password."}
                    try:
                        zf.extractall(
                            extract_dir,
                            pwd=password.encode("utf-8") if is_encrypted and password else None,
                        )
                    except RuntimeError as e:
                        if "Bad password" in str(e):
                            return {"status": "error", "message": "Incorrect ZIP password"}
                        raise

                for root, _, files in os.walk(extract_dir):
                    for extracted_file in files:
                        extracted_path = os.path.join(root, extracted_file)
                        try:
                            result = _run_pipeline(
                                extracted_path, extracted_file,
                                db, scan, password, realm_name,
                            )
                            all_results.append({
                                "filename": extracted_file,
                                "status": result.get("status", "success"),
                                "scan_result": result,
                            })
                        except Exception as fe:
                            logger.error("Error processing %s: %s", extracted_file, fe)
                            all_results.append({
                                "filename": extracted_file,
                                "status": "error",
                                "error": str(fe),
                            })
            finally:
                shutil.rmtree(extract_dir, ignore_errors=True)

        # ── Single file ───────────────────────────────────────────────────────
        else:
            if filename_lower.endswith(".pdf"):
                if _check_pdf_protected(temp_path) and not password:
                    return {"status": "error",
                            "message": "PDF is password-protected. Please provide a password."}

            result = _run_pipeline(
                temp_path, original_filename, db, scan, password, realm_name,
            )
            all_results.append({
                "filename": original_filename,
                "status": result.get("status", "success"),
                "scan_result": result,
            })

        db.commit()
        logger.info("scan_file completed: scan_id=%s files=%d", scan.id, len(all_results))

        # Return full unified output for single file; summary for ZIP
        if len(all_results) == 1:
            single = all_results[0].get("scan_result", {})
            single["file_count"] = 1
            single["results"] = all_results
            return single

        return {
            "status": "success",
            "data": {
                "scan_id": scan.id,
                "file_count": len(all_results),
                "results": all_results,
            },
        }

    except Exception as exc:
        db.rollback()
        logger.exception("scan_file error")
        msg = str(exc)
        if "PyCryptodome" in msg:
            return {"status": "error", "message": "Missing PyCryptodome for encrypted PDF",
                    "solution": "pip install pycryptodome"}
        return {"status": "error", "message": msg}

    finally:
        if temp_path and os.path.exists(temp_path):
            os.remove(temp_path)
        db.close()


# ── Endpoint ──────────────────────────────────────────────────────────────────

@router.post("/scan-file")
async def scan_file(
    file: UploadFile = File(...),
    realm_name: str = Form(None),
    password: str = Form(None),
    db: Session = Depends(get_db),
):
    """
    Upload a file and scan it through the full hybrid PII detection pipeline.

    Returns a unified JSON response containing:
    - document_metadata (doc_type, page_count, routing info)
    - entities (flat list with confidence + source)
    - pii_entities (grouped by type)
    - redactions (redaction map)
    - confidence_scores (per type)
    - processing_metrics (timing, engines used)
    - validation_results (passed, issues, coverage)
    """
    logger.info("scan_file: filename=%s realm=%s", file.filename, realm_name)
    file_bytes = await file.read()
    result = await run_in_threadpool(
        _scan_file_blocking,
        file_bytes, file.filename, realm_name, password, db,
    )
    return result
