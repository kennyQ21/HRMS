"""
Vault Migration Service — API routes.

Endpoints:
  GET  /status      → service health, engine status, model availability
  POST /scan-file   → upload any file, receive structured PII JSON

Supported file formats: PDF, DOCX, DOC, ODT, RTF, CSV, XLSX, XLS,
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
from fastapi import APIRouter, BackgroundTasks, Depends, File, Form, HTTPException, UploadFile
from fastapi.concurrency import run_in_threadpool
from sqlalchemy.orm import Session

from config import UPLOADS_DIR
from database import SessionLocal, get_db
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
from services.pii_analytics import calculate_distribution, calculate_risk_score, risk_level_from_score, summarize_entities
from services.pipeline_manager import get_pipeline
from services.post_processor import post_process
from services.job_store import complete_job, create_job, fail_job, get_job, update_job
from services.validator import validate_results
from schemas import ScanJobResponse, ScanStatusResponse

logger = logging.getLogger(__name__)
router = APIRouter(tags=["PII Scan"])

IMAGE_EXTENSIONS = (".jpg", ".jpeg", ".png", ".bmp", ".tif", ".tiff", ".webp")
HIDDEN_ZIP_NAMES = {".DS_Store"}
STAGE_PROGRESS = {
    "INITIALIZING": 2,
    "PARSING": 10,
    "OCR_PROCESSING": 35,
    "DETECTING_PII": 65,
    "ENTITY_RESOLUTION": 85,
    "PERSISTING_RESULTS": 95,
}


def _is_hidden_or_system_file(name: str) -> bool:
    base = os.path.basename(name)
    return (
        base in HIDDEN_ZIP_NAMES
        or base.startswith("._")
        or base.startswith(".")
        or "__MACOSX" in name
    )


def _build_processing_metrics_breakdown(result: dict, fallback_total_ms: int) -> dict:
    metrics = result.get("processing_metrics", {}) if isinstance(result, dict) else {}
    total_ms = float(metrics.get("total_ms", fallback_total_ms))
    return {
        "total_ms": total_ms,
        "ocr_ms": float(metrics.get("ocr_ms", 0.0)),
        "detection_ms": float(metrics.get("detection_ms", 0.0)),
        "resolution_ms": float(metrics.get("resolution_ms", 0.0)),
    }


def _normalized_distribution_from_entities(entities: list[dict]) -> dict[str, int]:
    distribution: dict[str, int] = {}
    for entity in entities:
        pii_type = str(entity.get("type", "UNKNOWN")).upper()
        if pii_type == "ORGANIZATION":
            continue
        distribution[pii_type] = distribution.get(pii_type, 0) + 1
    return distribution


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
    job_id: Optional[str] = None,
) -> dict:
    t0  = time.perf_counter()
    sl  = StageLogger(filename, scan.id)
    sl.header()

    pipeline = get_pipeline()

    with pipeline.begin("scan-file", source=filename) as ctx:

        # ── 1. Ingestion plan ─────────────────────────────────────────────────
        plan = dispatch_ingestion(temp_path, filename, password)
        if job_id:
            update_job(
                job_id,
                status="RUNNING",
                current_stage="PARSING",
                progress=STAGE_PROGRESS["PARSING"],
                current_file=filename,
            )
        sl.stage("ROUTE",
                 f"profile=structured={plan.document_profile.is_structured} "
                 f"medical={plan.document_profile.is_medical} "
                 f"ocr={plan.document_profile.needs_ocr}  "
                 f"parser={plan.parser_type}")

        if plan.parser_type == "unknown":
            sl.error("Unsupported file format")
            return build_error_response(filename, "Unsupported file format")

        # ── 2. Parse ──────────────────────────────────────────────────────────
        parser = _get_parser(filename, password)
        if parser is None:
            sl.error("No parser available")
            return build_error_response(filename, "No parser available for this format")

        is_image = filename.lower().endswith(IMAGE_EXTENSIONS)
        if job_id and (is_image or plan.document_profile.needs_ocr):
            update_job(
                job_id,
                current_stage="OCR_PROCESSING",
                progress=STAGE_PROGRESS["OCR_PROCESSING"],
            )
        t_ocr = time.perf_counter()
        if is_image:
            parsed_data = parser.parse_with_boxes(temp_path)
            ocr_output  = [{"text": parsed_data["data"][0].get("content", ""),
                             "lines": parsed_data.get("lines", []),
                             "ocr_quality": parsed_data.get("ocr_quality")}]
        else:
            parsed_data = parser.parse(temp_path)
            ocr_output  = None
        ocr_ms = (time.perf_counter() - t_ocr) * 1000

        if not parser.validate(parsed_data):
            sl.error("Invalid file structure")
            return build_error_response(filename, "Invalid file structure")

        sl.stage("PARSE",
                 f"chars={len(parsed_data['data'][0].get('content',''))}  "
                 f"ocr={'yes' if (is_image or plan.document_profile.needs_ocr) else 'no'}")

        # ── 3. Content reconstruction ─────────────────────────────────────────
        content_doc  = reconstruct_content(
            filename=filename,
            parser_output=parsed_data,
            ocr_output=ocr_output,
            file_metadata={"doc_type": plan.doc_type},
        )
        working_text = content_doc.full_text or \
                       (parsed_data["data"][0].get("content", "") if parsed_data.get("data") else "")

        # ── 3b. OCR normalisation ─────────────────────────────────────────────
        # Clean Indic ZWJ/ZWNJ, Arabic diacritics, PUA chars, tab runs,
        # and repeated punctuation before feeding text to detection engines.
        from services.ocr_normalizer import clean_ocr
        working_text = clean_ocr(working_text)

        sl.stage("RECONSTRUCT",
                 f"blocks={len(content_doc.blocks)}  chars={len(working_text)}")

        # ── 4. Detection ──────────────────────────────────────────────────────
        t_detect = time.perf_counter()
        dispatch_result = dispatch_detection(
            text=working_text,
            doc_type=plan.doc_type,
        )
        detection_total_ms = (time.perf_counter() - t_detect) * 1000
        if job_id:
            update_job(
                job_id,
                current_stage="DETECTING_PII",
                progress=STAGE_PROGRESS["DETECTING_PII"],
            )
        resolved_raw   = dispatch_result.resolved
        engine_results = dispatch_result.engine_results
        lang           = dispatch_result.language
        engine_ms      = sum(getattr(er, "duration_ms", 0.0) for er in engine_results)
        detection_ms   = engine_ms
        resolution_ms  = max(detection_total_ms - engine_ms, 0.0)
        # Spans from detection engines are in NORMALISED coordinate space.
        # The validator must receive the same normalised text so that
        # text[span.start:span.end] resolves to the matched value.
        norm_text = (
            dispatch_result.normalised_text.normalised
            if dispatch_result.normalised_text
            else working_text
        )
        ctx.record_engines(engine_results)

        lang_info = f"lang={lang.primary_lang} foreign={lang.has_foreign}" if lang else ""
        engine_summary = "  ".join(
            f"{e.engine}={len(e.matches)}" for e in engine_results
        )
        sl.stage("DETECT", f"{lang_info}  {engine_summary}".strip())

        # ── 5. Map semantic entities to OCR bounding boxes (for images) ────────
        if is_image and ocr_output:
            from services.bbox_mapper import map_entities_to_bboxes
            ocr_lines = []
            for ocr_page in (ocr_output or []):
                ocr_lines.extend(ocr_page.get("lines", []))
            resolved_raw = map_entities_to_bboxes(
                resolved_raw, ocr_lines, norm_text
            )

            from services.ocr_validator import validate_ocr_alignment
            ocr_report = validate_ocr_alignment(
                resolved_raw,
                ocr_lines,
                parsed_data.get("ocr_quality"),
            )
            if not ocr_report.passed or ocr_report.manual_review_required:
                logger.warning("[OCR-VALIDATOR] issues=%s", ocr_report.issues)

        # ── 5a. Post-processing — precision filter ────────────────────────────
        resolved = post_process(resolved_raw)
        if job_id:
            update_job(
                job_id,
                current_stage="ENTITY_RESOLUTION",
                progress=STAGE_PROGRESS["ENTITY_RESOLUTION"],
            )

        # ── 5a-guard. Entity count protection ─────────────────────────────────
        if len(resolved) > MAX_ENTITY_COUNT:
            logger.warning(
                "[GUARDRAIL] %d entities exceeds cap %d — truncating to top %d by confidence",
                len(resolved), MAX_ENTITY_COUNT, MAX_ENTITY_COUNT,
            )
            resolved.sort(key=lambda e: e.confidence, reverse=True)
            resolved = resolved[:MAX_ENTITY_COUNT]

        sl.stage("POST-PROCESS",
                 f"{len(resolved_raw)} raw → {len(resolved)} kept")


        # ── 5. Persist to DB ──────────────────────────────────────────────────
        counts = resolved_to_pii_counts(resolved)
        primary_type, primary_count, _ = select_primary_from_resolved(resolved)
        if job_id:
            distribution = calculate_distribution(resolved)
            summary = summarize_entities(resolved)
            update_job(
                job_id,
                current_stage="PERSISTING_RESULTS",
                progress=STAGE_PROGRESS["PERSISTING_RESULTS"],
                total_entities=summary["total_entities"],
                distribution=distribution,
                summary=summary,
            )

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
        # Pass normalised text — spans are in normalised coordinate space
        validation = validate_results(text=norm_text, resolved_entities=resolved)
        sl.stage("VALIDATE",
                 f"passed={validation.passed}  issues={len(validation.issues)}")

        # ── 7. Build output ───────────────────────────────────────────────────
        elapsed_ms   = (time.perf_counter() - t0) * 1000
        lang_code    = lang.primary_lang if lang else "en"
        result       = build_scan_response(
            scan_id=scan.id,
            filename=filename,
            resolved_entities=resolved,
            engine_results=engine_results,
            content_doc=content_doc,
            ingestion_plan=plan,
            validation_report=validation,
            elapsed_ms=elapsed_ms,
            language=lang_code,
            ocr_ms=ocr_ms,
            detection_ms=detection_ms,
            resolution_ms=resolution_ms,
        )
        timeout_warnings = [
            f"{e.engine}_timeout" for e in engine_results
            if getattr(e, "error", None) == "timeout"
        ]
        if timeout_warnings:
            result["warnings"] = timeout_warnings
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


def _run_scan_job(job_id: str, temp_path: str, original_filename: str, password: Optional[str]) -> None:
    db = SessionLocal()
    try:
        scan = Scan(
            name=f"Scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
            connector_id="file_upload",
            realm_name=None,
        )
        db.add(scan)
        db.flush()

        fname_lower = original_filename.lower()
        update_job(job_id, status="RUNNING", current_stage="INITIALIZING", progress=STAGE_PROGRESS["INITIALIZING"])

        if fname_lower.endswith(".zip"):
            extract_dir = tempfile.mkdtemp(prefix="zip_")
            try:
                with zipfile.ZipFile(temp_path, "r") as zf:
                    encrypted = any(zi.flag_bits & 0x1 for zi in zf.filelist)
                    if encrypted and not password:
                        raise ValueError("ZIP is password-protected — supply a password.")
                    zf.extractall(
                        extract_dir,
                        pwd=password.encode() if encrypted and password else None,
                    )

                members: list[tuple[str, str]] = []
                skipped_members: list[str] = []
                for root, _, files in os.walk(extract_dir):
                    for file_name in files:
                        rel_path = os.path.relpath(os.path.join(root, file_name), extract_dir)
                        if _is_hidden_or_system_file(rel_path):
                            skipped_members.append(file_name)
                            continue
                        members.append((os.path.join(root, file_name), file_name))

                update_job(
                    job_id,
                    total_files=len(members),
                    processed_files=0,
                    failed_files=0,
                    skipped_files=len(skipped_members),
                    skipped=skipped_members,
                )

                aggregate_distribution: dict[str, int] = {}
                file_summaries = []
                detailed_results = []

                for index, (member_path, member_name) in enumerate(members):
                    update_job(job_id, current_file=member_name)
                    file_t0 = time.perf_counter()
                    try:
                        result = _run_pipeline(member_path, member_name, db, scan, password, job_id=job_id)
                        entities = result.get("entities", [])
                        normalized_entities = []
                        for entity in entities:
                            cloned = dict(entity)
                            cloned["type"] = str(cloned.get("type", "UNKNOWN")).upper()
                            normalized_entities.append(cloned)

                        distribution = _normalized_distribution_from_entities(normalized_entities)
                        for pii_type, count in distribution.items():
                            aggregate_distribution[pii_type] = aggregate_distribution.get(pii_type, 0) + count

                        processing_metrics = _build_processing_metrics_breakdown(
                            result, int((time.perf_counter() - file_t0) * 1000)
                        )

                        file_summaries.append({
                            "file_name": member_name,
                            "status": "COMPLETED",
                            "entities": sum(distribution.values()),
                            "distribution": distribution,
                            "risk_level": risk_level_from_score(calculate_risk_score(distribution), distribution),
                            "processing_metrics": processing_metrics,
                        })
                        detailed_results.append({
                            "file_name": member_name,
                            "entities": normalized_entities,
                        })
                        processed = index + 1
                        progress = int((processed / max(len(members), 1)) * 100)
                        summary_score = calculate_risk_score(aggregate_distribution)
                        update_job(
                            job_id,
                            processed_files=processed,
                            progress=min(progress, 99),
                            distribution=aggregate_distribution,
                            total_entities=sum(aggregate_distribution.values()),
                            files=file_summaries,
                            detailed_results=detailed_results,
                            summary={
                                "total_entities": sum(aggregate_distribution.values()),
                                "unique_types": len(aggregate_distribution),
                                "risk_score": summary_score,
                                "risk_level": risk_level_from_score(summary_score, aggregate_distribution),
                            },
                        )
                    except Exception as exc:
                        logger.error("ZIP member %s failed: %s", member_name, exc)
                        snapshot = get_job(job_id) or {}
                        failed_files = int(snapshot.get("failed_files", 0)) + 1
                        processed = int(snapshot.get("processed_files", 0)) + 1
                        errors = list(snapshot.get("errors", []))
                        errors.append(f"{member_name}: {exc}")
                        file_summaries.append({
                            "file_name": member_name,
                            "status": "FAILED",
                            "entities": 0,
                            "distribution": {},
                            "risk_level": "LOW",
                            "processing_metrics": {
                                "total_ms": float(int((time.perf_counter() - file_t0) * 1000)),
                                "ocr_ms": 0.0,
                                "detection_ms": 0.0,
                                "resolution_ms": 0.0,
                            },
                        })
                        update_job(
                            job_id,
                            failed_files=failed_files,
                            processed_files=processed,
                            files=file_summaries,
                            errors=errors,
                        )

                db.commit()
                summary_score = calculate_risk_score(aggregate_distribution)
                update_job(
                    job_id,
                    summary={
                        "total_entities": sum(aggregate_distribution.values()),
                        "unique_types": len(aggregate_distribution),
                        "risk_score": summary_score,
                        "risk_level": risk_level_from_score(summary_score, aggregate_distribution),
                    },
                    distribution=aggregate_distribution,
                    files=file_summaries,
                    detailed_results=detailed_results,
                )
                complete_job(job_id)
            finally:
                shutil.rmtree(extract_dir, ignore_errors=True)
            return

        if fname_lower.endswith(".pdf") and _is_pdf_protected(temp_path) and not password:
            raise ValueError("PDF is password-protected — supply a password.")

        t0 = time.perf_counter()
        result = _run_pipeline(temp_path, original_filename, db, scan, password, job_id=job_id)
        db.commit()
        result["file_count"] = 1
        entities = result.get("entities", [])
        normalized_entities = []
        for entity in entities:
            cloned = dict(entity)
            cloned["type"] = str(cloned.get("type", "UNKNOWN")).upper()
            normalized_entities.append(cloned)
        result["entities"] = normalized_entities
        distribution = _normalized_distribution_from_entities(normalized_entities)
        score = calculate_risk_score(distribution)
        file_summary = {
            "file_name": original_filename,
            "status": "COMPLETED",
            "entities": sum(distribution.values()),
            "distribution": distribution,
            "risk_level": risk_level_from_score(score, distribution),
            "processing_metrics": _build_processing_metrics_breakdown(
                result, int((time.perf_counter() - t0) * 1000)
            ),
        }
        result["summary"] = {
            "total_entities": sum(distribution.values()),
            "unique_types": len(distribution),
            "risk_score": score,
            "risk_level": risk_level_from_score(score, distribution),
        }
        result["distribution"] = distribution
        result["files"] = [file_summary]
        update_job(
            job_id,
            total_files=1,
            processed_files=1,
            skipped_files=0,
            failed_files=0,
            total_entities=result["summary"]["total_entities"],
            distribution=distribution,
            files=[file_summary],
            summary=result["summary"],
            detailed_results=[{"file_name": original_filename, "entities": normalized_entities}],
            skipped=[],
        )
        complete_job(job_id)
    except Exception as exc:
        db.rollback()
        logger.exception("scan job unhandled error")
        fail_job(job_id, str(exc))
    finally:
        db.close()
        if temp_path and os.path.exists(temp_path):
            os.remove(temp_path)


# ── GET /status ───────────────────────────────────────────────────────────────

@router.get("/status", summary="Service health and engine status")
async def status():
    """Small operational health snapshot."""
    import requests as _requests
    from services.detection_dispatcher import _gliner_engine
    from services.ocr_engine import _get_ocr

    try:
        gliner_loaded = _gliner_engine.cache_info().currsize > 0
    except Exception:
        gliner_loaded = False

    try:
        ocr_loaded = _get_ocr.cache_info().currsize > 0
    except Exception:
        ocr_loaded = False

    ollama_ok = False
    try:
        r = _requests.get("http://localhost:11434/api/tags", timeout=2)
        ollama_ok = r.status_code == 200
    except Exception:
        pass

    return {
        "regex": "healthy",
        "gliner": "healthy" if gliner_loaded else "available",
        "qwen": "available" if ollama_ok else "unavailable",
        "ocr": "healthy" if ocr_loaded else "available",
        "version": "2.x",
        "pipeline_mode": "deterministic_semantic_hybrid",
    }


# ── POST /scan-file ───────────────────────────────────────────────────────────

# ── Production guardrails ─────────────────────────────────────────────────────

MAX_FILE_SIZE_MB = 100          # Reject files larger than 100 MB
MAX_ENTITY_COUNT = 500          # Safety cap on detected entities
MAX_OCR_SECONDS = 120           # OCR timeout per file


@router.post("/scan-file", summary="Scan a file for PII", response_model=ScanJobResponse)
async def scan_file(
    background_tasks: BackgroundTasks,
    file: UploadFile = File(..., description="File to scan"),
    password: Optional[str] = Form(None, description="Password for encrypted PDF/ZIP"),
):
    """
    Upload any supported file → receive document-centric PII JSON.

    **Supported formats**: PDF · DOCX · DOC · ODT · RTF · CSV · XLSX · XLS ·
    JPG · PNG · BMP · TIFF · WEBP · MDB · SQL · ZIP

    **Returns**: `document_metadata`, `entities`, `entity_groups`,
    `document_hints`, `ocr`, `validation_results`, `redactions`,
    `processing_metrics`.

    **Limits**: Max file size 100 MB. Max 500 entities per file.
    """
    # ── File size guardrail ───────────────────────────────────────────────────
    file_bytes = await file.read()
    file_size_mb = len(file_bytes) / (1024 * 1024)
    if file_size_mb > MAX_FILE_SIZE_MB:
        return build_error_response(
            file.filename,
            f"File too large: {file_size_mb:.1f} MB exceeds {MAX_FILE_SIZE_MB} MB limit"
        )

    logger.info("▷ Received: %s  (%.1f KB)",
                file.filename, file_size_mb * 1024)
    suffix = os.path.splitext(file.filename)[1]
    with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as tmp:
        tmp.write(file_bytes)
        temp_path = tmp.name

    job_id = create_job(file.filename or "uploaded_file")
    background_tasks.add_task(_run_scan_job, job_id, temp_path, file.filename, password)
    return {"job_id": job_id, "status": "QUEUED"}


@router.get("/scan-status/{job_id}", summary="Get scan progress and analytics", response_model=ScanStatusResponse)
async def scan_status(job_id: str):
    job = get_job(job_id)
    if not job:
        raise HTTPException(status_code=404, detail=f"Job '{job_id}' not found")

    started_at = job.get("started_at")
    completed_at = job.get("completed_at")
    elapsed_seconds = 0
    try:
        start_dt = datetime.fromisoformat(started_at) if started_at else None
        end_dt = datetime.fromisoformat(completed_at) if completed_at else datetime.now(start_dt.tzinfo) if start_dt else datetime.utcnow()
        if start_dt:
            elapsed_seconds = int((end_dt - start_dt).total_seconds())
    except Exception:
        elapsed_seconds = 0

    return {
        "job_id": job["job_id"],
        "status": job["status"],
        "progress": job["progress"],
        "current_stage": job.get("current_stage") or "",
        "total_files": job.get("total_files", 1),
        "processed_files": job.get("processed_files", 0),
        "skipped_files": job.get("skipped_files", 0),
        "failed_files": job.get("failed_files", 0),
        "current_file": job.get("current_file"),
        "summary": job.get("summary") or {
            "total_entities": 0,
            "unique_types": 0,
            "risk_score": 0.0,
            "risk_level": "LOW",
        },
        "distribution": job.get("distribution") or {},
        "files": job.get("files", []),
        "detailed_results": job.get("detailed_results", []),
        "skipped": job.get("skipped", []),
        "errors": job.get("errors", []),
        "started_at": started_at,
        "completed_at": completed_at,
        "elapsed_seconds": elapsed_seconds,
    }


# ── POST /redact-file ─────────────────────────────────────────────────────────

def _redact_blocking(
    file_bytes: bytes,
    original_filename: str,
    password: Optional[str],
    redaction_type: str,
    db,
) -> dict:
    """Run full scan pipeline then apply redaction. Returns scan JSON + base64 redacted file."""
    import base64
    from services.redaction_engine import RedactionEngine, REDACT_FULL, REDACT_PARTIAL, REDACT_CONTEXTUAL, REDACT_MASK

    # ── Run the scan pipeline first ───────────────────────────────────────────
    scan_result = _scan_blocking(file_bytes, original_filename, password, db)
    if scan_result.get("status") == "error":
        return scan_result

    # ── Apply redaction ───────────────────────────────────────────────────────
    import tempfile
    rtype_map = {
        "full": REDACT_FULL,
        "partial": REDACT_PARTIAL,
        "contextual": REDACT_CONTEXTUAL,
        "mask": REDACT_MASK,
    }
    rtype = rtype_map.get(redaction_type, REDACT_CONTEXTUAL)

    # Re-run pipeline to get resolved entities for redaction
    # (scan_blocking already ran; we reconstruct entities from the JSON output)
    entities_raw = scan_result.get("entities", [])

    # Write file to temp path for redaction engine
    suffix = os.path.splitext(original_filename)[1]
    try:
        with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as tmp:
            tmp.write(file_bytes)
            tmp_path = tmp.name

        # Build minimal entity objects that redaction engine accepts
        from services.entity_resolution import ResolvedEntity
        entities = []
        for e in entities_raw:
            span = e.get("span") or {}
            entities.append(ResolvedEntity(
                pii_type=e["type"],
                value=e["value"],
                confidence=e["confidence"],
                sources=[e.get("source", "regex")],
                start=span.get("start", -1),
                end=span.get("end", -1),
                sensitivity="High",
            ))

        engine = RedactionEngine()
        result = engine.redact(
            file_path=tmp_path,
            filename=original_filename,
            entities=entities,
            redaction_type=rtype,
        )

        redacted_b64 = base64.b64encode(result.redacted_bytes).decode("utf-8")
        redacted_filename = f"redacted_{original_filename}"

        # Content type lookup
        ext = suffix.lower()
        ct_map = {
            ".pdf": "application/pdf",
            ".docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            ".xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            ".csv": "text/csv",
            ".jpg": "image/jpeg", ".jpeg": "image/jpeg",
            ".png": "image/png",
        }
        content_type = ct_map.get(ext, "application/octet-stream")

        # Update the redaction map in the scan result
        scan_result["redactions"] = {
            "map":   result.redaction_map,
            "count": result.entity_count,
            "redaction_verification": result.redaction_verification,
        }

        return {
            "status":       "success",
            "scan":         scan_result,
            "redacted_file": {
                "filename":     redacted_filename,
                "format":       result.format,
                "content_type": content_type,
                "data_base64":  redacted_b64,
                "entities_redacted": result.entity_count,
                "redaction_type": redaction_type,
                "redaction_verification": result.redaction_verification,
                "error": result.error,
            },
        }

    except Exception as exc:
        logger.exception("redact_file error")
        return {"status": "error", "message": str(exc)}
    finally:
        try:
            os.remove(tmp_path)
        except Exception:
            pass


@router.post("/redact-file", summary="Scan and redact a file")
async def redact_file(
    file:            UploadFile    = File(..., description="File to scan and redact"),
    password:        Optional[str] = Form(None,          description="Password for encrypted PDF/ZIP"),
    redaction_type:  str           = Form("contextual",  description="full | partial | contextual | mask"),
    db:              Session       = Depends(get_db),
):
    """
    Upload any supported file → scan for PII → return:
    1. Full scan JSON (same as `/scan-file`)
    2. Redacted file as **base64** in `redacted_file.data_base64`

    **Redaction types**:
    - `contextual` *(default)* — replaces value with `[PERSON_NAME]`, `[AADHAAR]` etc.
    - `full`    — replaces with `XXXXXXXXXXXX`
    - `partial` — masks middle digits: `XXXX-XXXX-1234`
    - `mask`    — black rectangle overlay (PDF only)

    **Decode the redacted file** (Python example):
    ```python
    import base64
    data = response["redacted_file"]["data_base64"]
    with open("redacted.pdf", "wb") as f:
        f.write(base64.b64decode(data))
    ```
    """
    logger.info("▷ Redact: %s  type=%s", file.filename, redaction_type)
    await file.seek(0)
    file_bytes = await file.read()

    return await run_in_threadpool(
        _redact_blocking,
        file_bytes, file.filename, password, redaction_type, db,
    )
