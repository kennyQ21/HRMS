"""
POST /scan-file
---------------
Upload any supported file → receive PII detection JSON.

Supported formats: PDF, DOCX, DOC, ODT, RTF, CSV, XLSX, XLS,
                   JPG, PNG, BMP, TIFF, WEBP, MDB, SQL, ZIP
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
from database import get_db
from models import ColumnScan, Scan, ScanAnomaly
from parsers.structured.csv_parser import CSVParser
from parsers.structured.excel_parser import ExcelParser
from parsers.unstructured.access_parser import MDBParser
from parsers.unstructured.document_parser import DocumentParser, ImageParser, PDFParser
from parsers.unstructured.sql_parser import SQLParser
from services.content_reconstruction import reconstruct_content
from services.detection_dispatcher import dispatch_detection
from services.entity_resolution import resolved_to_pii_counts, select_primary_from_resolved
from services.ingestion_dispatcher import dispatch_ingestion
from services.output_schema import build_error_response, build_scan_response
from services.pipeline_manager import get_pipeline
from services.post_processor import post_process
from services.validator import validate_results

logger = logging.getLogger(__name__)
router = APIRouter(tags=["PII Scan"])

IMAGE_EXTENSIONS = (".jpg", ".jpeg", ".png", ".bmp", ".tif", ".tiff", ".webp")


# ── Parser factory ────────────────────────────────────────────────────────────

def _get_parser(filename: str, password: Optional[str] = None):
    fn = filename.lower()
    if fn.endswith((".xlsx", ".xls")):                      return ExcelParser()
    if fn.endswith(".csv"):                                  return CSVParser()
    if fn.endswith((".docx", ".doc", ".odt", ".rtf")):      return DocumentParser()
    if fn.endswith(".pdf"):                                  return PDFParser(password=password)
    if fn.endswith(IMAGE_EXTENSIONS):                       return ImageParser()
    if fn.endswith(".mdb"):                                  return MDBParser()
    if fn.endswith(".sql"):                                  return SQLParser()
    return None


def _is_pdf_protected(path: str) -> bool:
    try:
        with open(path, "rb") as f:
            return PyPDF2.PdfReader(f).is_encrypted
    except Exception:
        return False


# ── Stage logger ──────────────────────────────────────────────────────────────

class StageLogger:
    """Prints a clear progress banner for each pipeline stage to the terminal."""

    DIVIDER = "─" * 60

    def __init__(self, filename: str, scan_id: int):
        self.filename  = filename
        self.scan_id   = scan_id
        self.t_start   = time.perf_counter()
        self._stage_t  = self.t_start

    def header(self):
        logger.info(self.DIVIDER)
        logger.info("▶  SCAN #%d  |  %s  |  %s",
                    self.scan_id, self.filename,
                    datetime.now().strftime("%H:%M:%S"))
        logger.info(self.DIVIDER)

    def stage(self, name: str, detail: str = ""):
        elapsed = time.perf_counter() - self._stage_t
        self._stage_t = time.perf_counter()
        suffix = f"  [{detail}]" if detail else ""
        logger.info("  %-14s ✓  %.2fs%s", name, elapsed, suffix)

    def footer(self, entity_count: int):
        total = time.perf_counter() - self.t_start
        logger.info(self.DIVIDER)
        logger.info("✔  DONE  |  %d entities found  |  %.2fs total", entity_count, total)
        logger.info(self.DIVIDER)

    def error(self, msg: str):
        logger.error("✘  FAILED  |  %s  |  %.2fs", msg,
                     time.perf_counter() - self.t_start)


# ── Core pipeline (one file) ──────────────────────────────────────────────────

def _run_pipeline(
    temp_path: str,
    filename: str,
    db: Session,
    scan: Scan,
    password: Optional[str],
) -> dict:
    t0  = time.perf_counter()
    sl  = StageLogger(filename, scan.id)
    sl.header()

    pipeline = get_pipeline()

    with pipeline.begin("scan-file", source=filename) as ctx:

        # ── 1. Ingestion plan ─────────────────────────────────────────────────
        plan = dispatch_ingestion(temp_path, filename, password)
        sl.stage("ROUTE",
                 f"doc_type={plan.doc_type}  parser={plan.parser_type}  "
                 f"ocr={'yes' if plan.needs_ocr else 'no'}")

        if plan.parser_type == "unknown":
            sl.error("Unsupported file format")
            return build_error_response(filename, "Unsupported file format")

        # ── 2. Parse ──────────────────────────────────────────────────────────
        parser = _get_parser(filename, password)
        if parser is None:
            sl.error("No parser available")
            return build_error_response(filename, "No parser available for this format")

        is_image = filename.lower().endswith(IMAGE_EXTENSIONS)
        if is_image:
            parsed_data = parser.parse_with_boxes(temp_path)
            ocr_output  = [{"text": parsed_data["data"][0].get("content", ""),
                             "lines": parsed_data.get("lines", [])}]
        else:
            parsed_data = parser.parse(temp_path)
            ocr_output  = None

        if not parser.validate(parsed_data):
            sl.error("Invalid file structure")
            return build_error_response(filename, "Invalid file structure")

        sl.stage("PARSE",
                 f"chars={len(parsed_data['data'][0].get('content',''))}  "
                 f"ocr={'yes' if (is_image or plan.needs_ocr) else 'no'}")

        # ── 3. Content reconstruction ─────────────────────────────────────────
        content_doc  = reconstruct_content(
            filename=filename,
            parser_output=parsed_data,
            ocr_output=ocr_output,
            file_metadata={"doc_type": plan.doc_type},
        )
        working_text = content_doc.full_text or \
                       (parsed_data["data"][0].get("content", "") if parsed_data.get("data") else "")
        sl.stage("RECONSTRUCT",
                 f"blocks={len(content_doc.blocks)}  chars={len(working_text)}")

        # ── 4. Detection ──────────────────────────────────────────────────────
        dispatch_result = dispatch_detection(
            text=working_text,
            doc_type=plan.doc_type,
        )
        resolved_raw   = dispatch_result.resolved
        engine_results = dispatch_result.engine_results
        lang           = dispatch_result.language
        ctx.record_engines(engine_results)

        lang_info = f"lang={lang.primary_lang} foreign={lang.has_foreign}" if lang else ""
        engine_summary = "  ".join(
            f"{e.engine}={len(e.matches)}" for e in engine_results
        )
        sl.stage("DETECT", f"{lang_info}  {engine_summary}".strip())

        # ── 5a. Post-processing — precision filter ────────────────────────────
        resolved = post_process(resolved_raw)
        sl.stage("POST-PROCESS",
                 f"{len(resolved_raw)} raw → {len(resolved)} kept")

        # ── 5. Persist to DB ──────────────────────────────────────────────────
        counts = resolved_to_pii_counts(resolved)
        primary_type, primary_count, _ = select_primary_from_resolved(resolved)

        col_scan = ColumnScan(
            db_name=filename,
            table_name="file",
            column_name="content",
            total_rows=1,
            primary_pii_type=primary_type,
            primary_pii_match_count=primary_count or 0,
            scan=scan,
        )
        db.add(col_scan)
        for pii_id, cnt in counts.items():
            db.add(ScanAnomaly(
                pii_type=pii_id,
                match_count=cnt,
                column_scan=col_scan,
            ))

        if is_image:
            dest = UPLOADS_DIR / str(scan.id)
            dest.mkdir(parents=True, exist_ok=True)
            shutil.copy2(temp_path, dest / os.path.basename(filename))

        sl.stage("PERSIST",
                 f"{len(resolved)} entities → DB  scan_id={scan.id}")

        # ── 6. Validate ───────────────────────────────────────────────────────
        validation = validate_results(text=working_text, resolved_entities=resolved)
        sl.stage("VALIDATE",
                 f"passed={validation.passed}  issues={len(validation.issues)}")

        # ── 7. Build output ───────────────────────────────────────────────────
        elapsed_ms = (time.perf_counter() - t0) * 1000
        result     = build_scan_response(
            scan_id=scan.id,
            filename=filename,
            resolved_entities=resolved,
            engine_results=engine_results,
            content_doc=content_doc,
            ingestion_plan=plan,
            validation_report=validation,
            elapsed_ms=elapsed_ms,
        )
        sl.footer(len(resolved))
        return result


# ── Blocking wrapper (handles ZIP + single file) ──────────────────────────────

def _scan_blocking(
    file_bytes: bytes,
    original_filename: str,
    password: Optional[str],
    db: Session,
) -> dict:
    temp_path = None
    try:
        suffix = os.path.splitext(original_filename)[1]
        with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as tmp:
            tmp.write(file_bytes)
            temp_path = tmp.name

        scan = Scan(
            name=f"Scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
            connector_id="file_upload",
            realm_name=None,
        )
        db.add(scan)
        db.flush()

        fname_lower = original_filename.lower()

        # ── ZIP: unpack and scan every file inside ────────────────────────────
        if fname_lower.endswith(".zip"):
            extract_dir = tempfile.mkdtemp(prefix="zip_")
            try:
                with zipfile.ZipFile(temp_path, "r") as zf:
                    encrypted = any(zi.flag_bits & 0x1 for zi in zf.filelist)
                    if encrypted and not password:
                        return {"status": "error",
                                "message": "ZIP is password-protected — supply a password."}
                    zf.extractall(
                        extract_dir,
                        pwd=password.encode() if encrypted and password else None,
                    )

                all_results = []
                for root, _, files in os.walk(extract_dir):
                    for f in files:
                        fpath = os.path.join(root, f)
                        try:
                            r = _run_pipeline(fpath, f, db, scan, password)
                            all_results.append({"filename": f, "status": r.get("status", "success"), "scan_result": r})
                        except Exception as exc:
                            logger.error("ZIP member %s failed: %s", f, exc)
                            all_results.append({"filename": f, "status": "error", "error": str(exc)})

                db.commit()
                return {"status": "success", "file_count": len(all_results), "results": all_results}

            finally:
                shutil.rmtree(extract_dir, ignore_errors=True)

        # ── Single file ───────────────────────────────────────────────────────
        if fname_lower.endswith(".pdf") and _is_pdf_protected(temp_path) and not password:
            return {"status": "error", "message": "PDF is password-protected — supply a password."}

        result = _run_pipeline(temp_path, original_filename, db, scan, password)
        db.commit()
        result["file_count"] = 1
        return result

    except Exception as exc:
        db.rollback()
        logger.exception("scan_file unhandled error")
        return {"status": "error", "message": str(exc)}

    finally:
        if temp_path and os.path.exists(temp_path):
            os.remove(temp_path)
        db.close()


# ── Endpoint ──────────────────────────────────────────────────────────────────

@router.post("/scan-file", summary="Scan a file for PII")
async def scan_file(
    file:     UploadFile         = File(..., description="File to scan (PDF, DOCX, JPG, CSV, XLSX, ZIP, …)"),
    password: Optional[str]      = Form(None, description="Password for encrypted PDF or ZIP"),
    db:       Session            = Depends(get_db),
):
    """
    Upload any supported file and receive a structured JSON report of all
    PII entities detected inside it.

    **Supported formats**: PDF · DOCX · DOC · ODT · RTF · CSV · XLSX · XLS ·
    JPG · PNG · BMP · TIFF · WEBP · MDB · SQL · ZIP (archive of the above)

    **Returns**: unified PII JSON with `entities`, `pii_entities` (grouped),
    `confidence_scores`, `document_metadata`, `processing_metrics`, and
    `validation_results`.
    """
    logger.info("▷ Received: %s  (%.1f KB)",
                file.filename, len(await file.read()) / 1024)
    await file.seek(0)
    file_bytes = await file.read()

    return await run_in_threadpool(
        _scan_blocking,
        file_bytes, file.filename, password, db,
    )
