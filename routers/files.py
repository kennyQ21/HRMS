from __future__ import annotations
"""
Router: file PII scanning

Endpoints:
  POST /scan-file  – upload a file (or ZIP archive) and scan it for PII
"""

import logging
import os
import shutil
import tempfile
import zipfile
from datetime import datetime

import PyPDF2
from fastapi import APIRouter, Depends, File, Form, UploadFile
from fastapi.concurrency import run_in_threadpool
from sqlalchemy.orm import Session

from constants import PII_TYPES
from database import get_db
from models import Scan
from parsers.structured.csv_parser import CSVParser
from parsers.structured.excel_parser import ExcelParser
from parsers.unstructured.access_parser import MDBParser
from parsers.unstructured.document_parser import DocumentParser, ImageParser, PDFParser
from parsers.unstructured.sql_parser import SQLParser
from routers.scans import process_column_data, process_document_content

logger = logging.getLogger(__name__)

router = APIRouter(tags=["File Scanning"])
IMAGE_EXTENSIONS = (".jpg", ".jpeg", ".png", ".bmp", ".tif", ".tiff", ".webp")


# ── Helpers ───────────────────────────────────────────────────────────────────

def _check_pdf_is_protected(file_path: str) -> bool:
    """Return True if the PDF at file_path is password-protected."""
    try:
        with open(file_path, "rb") as f:
            return PyPDF2.PdfReader(f).is_encrypted
    except Exception:
        return False


def _get_parser(filename: str, password: str | None):
    """Return the appropriate parser for a given filename, or None if unsupported."""
    fn = filename.lower()
    if fn.endswith((".xlsx", ".xls")):
        return ExcelParser()
    if fn.endswith(".csv"):
        return CSVParser()
    if fn.endswith((".docx", ".doc", ".odt", ".rtf")):
        return DocumentParser()
    if fn.endswith(".pdf"):
        return PDFParser(password=password)
    if fn.endswith(IMAGE_EXTENSIONS):
        return ImageParser()
    if fn.endswith(".mdb"):
        return MDBParser()
    if fn.endswith(".sql"):
        return SQLParser()
    return None


def _process_parsed(db: Session, scan: Scan, filename: str, parsed_data: dict, connector_id: str):
    """Dispatch parsed data to the right column/document processing function."""
    fn = filename.lower()

    if fn.endswith((".pdf", ".docx", ".doc", ".odt", ".rtf", *IMAGE_EXTENSIONS)):
        text_content = parsed_data["data"][0].get("content", "")
        process_document_content(
            db, scan, connector_id, os.path.basename(filename), text_content, PII_TYPES
        )

    elif fn.endswith(".sql"):
        for item in parsed_data["data"]:
            content_type = item.get("content_type", "")
            text = item.get("content", "")
            if content_type == "full_sql":
                process_document_content(
                    db, scan, "sql_parser", os.path.basename(filename), text, PII_TYPES
                )
            elif content_type == "table_definition":
                table_name = item.get("table_name", "unknown_table")
                process_document_content(
                    db, scan, "sql_parser", os.path.basename(filename),
                    f"Table {table_name}: {text}", PII_TYPES
                )

    elif fn.endswith(".mdb"):
        for table_data in parsed_data["data"]:
            table_name = table_data["table_name"]
            for column in table_data["columns"]:
                values = [row.get(column) for row in table_data["rows"]]
                process_column_data(
                    db, scan, "mdb_parser", os.path.basename(filename),
                    table_name, column, values, PII_TYPES
                )

    else:
        # CSV / Excel
        table_label = "sheet1" if fn.endswith((".xlsx", ".xls")) else "data"
        ext = fn.rsplit(".", 1)[-1]
        for column in parsed_data["metadata"]["columns"]:
            values = [row.get(column) for row in parsed_data["data"]]
            process_column_data(
                db, scan, f"{ext}_parser", os.path.basename(filename),
                table_label, column, values, PII_TYPES
            )


def _scan_file_blocking(
    file_bytes: bytes,
    original_filename: str,
    realm_name: str | None,
    password: str | None,
    db: Session,
):
    """
    Full blocking implementation of /scan-file.
    Written as a plain function so it can be safely offloaded via run_in_threadpool.
    """
    all_results = []
    temp_path = None

    try:
        # Save upload to a temp file
        suffix = os.path.splitext(original_filename)[1]
        with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as tmp:
            tmp.write(file_bytes)
            temp_path = tmp.name

        # Create scan record
        scan = Scan(
            name=f"File_Scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
            connector_id="file_upload",
            realm_name=realm_name,
        )
        db.add(scan)
        db.flush()

        filename_lower = original_filename.lower()

        if filename_lower.endswith(".zip"):
            extract_dir = tempfile.mkdtemp(prefix="zip_extract_")
            try:
                with zipfile.ZipFile(temp_path, "r") as zf:
                    is_encrypted = any(zi.flag_bits & 0x1 for zi in zf.filelist)
                    if is_encrypted and not password:
                        return {
                            "status": "error",
                            "message": "ZIP file is password protected. Please provide a password.",
                        }
                    try:
                        zf.extractall(extract_dir, pwd=password.encode("utf-8") if is_encrypted and password else None)
                    except RuntimeError as e:
                        if "Bad password" in str(e):
                            return {"status": "error", "message": "Incorrect ZIP password"}
                        raise

                for root, _, files in os.walk(extract_dir):
                    for extracted_file in files:
                        extracted_path = os.path.join(root, extracted_file)
                        parser = _get_parser(extracted_file, password)

                        if parser is None:
                            all_results.append(
                                {"filename": extracted_file, "status": "skipped", "reason": "Unsupported file format"}
                            )
                            continue

                        try:
                            parsed_data = parser.parse(extracted_path)
                            if not parser.validate(parsed_data):
                                all_results.append(
                                    {"filename": extracted_file, "status": "error", "error": "Invalid file structure"}
                                )
                                continue

                            _process_parsed(db, scan, extracted_file, parsed_data, f"{extracted_file.rsplit('.',1)[-1]}_parser")
                            all_results.append(
                                {"filename": extracted_file, "status": "success", "metadata": parsed_data["metadata"]}
                            )

                        except Exception as fe:
                            msg = str(fe)
                            if any(k in msg.lower() for k in ("password required", "incorrect password")):
                                msg = "Password protected file. Please provide the correct password."
                            logger.error("Error processing %s: %s", extracted_file, msg)
                            all_results.append({"filename": extracted_file, "status": "error", "error": msg})

            finally:
                shutil.rmtree(extract_dir, ignore_errors=True)

        else:
            # PDF password-protection check before instantiating parser
            if filename_lower.endswith(".pdf"):
                if _check_pdf_is_protected(temp_path) and not password:
                    return {
                        "status": "error",
                        "message": "PDF is password protected. Please provide a password.",
                    }

            parser = _get_parser(original_filename, password)
            if parser is None:
                return {"status": "error", "message": "Unsupported file format"}

            try:
                parsed_data = parser.parse(temp_path)
                if not parser.validate(parsed_data):
                    raise ValueError("Invalid file structure")

                _process_parsed(db, scan, original_filename, parsed_data, f"{filename_lower.rsplit('.',1)[-1]}_parser")
                all_results.append(
                    {"filename": original_filename, "status": "success", "metadata": parsed_data["metadata"]}
                )

            except Exception as exc:
                msg = str(exc)
                if any(k in msg.lower() for k in ("password required", "incorrect password")):
                    return {"status": "error", "message": "Password protected file. Please provide the correct password."}
                raise

        db.commit()
        logger.info("scan_file completed: scan_id=%s files=%d", scan.id, len(all_results))

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
        msg = str(exc)
        logger.exception("scan_file error")

        if "PyCryptodome is required" in msg:
            return {
                "status": "error",
                "message": "Missing dependency: PyCryptodome is required for encrypted PDFs",
                "solution": "pip install pycryptodome",
            }
        return {"status": "error", "message": msg}

    finally:
        if temp_path and os.path.exists(temp_path):
            os.remove(temp_path)
        db.close()


# ── /scan-file ────────────────────────────────────────────────────────────────

@router.post("/scan-file")
async def scan_file(
    file: UploadFile = File(...),
    realm_name: str = Form(None),
    password: str = Form(None),
    db: Session = Depends(get_db),
):
    """
    Upload a file (or ZIP archive) and scan its contents for PII.

    Supported formats: CSV, Excel (.xlsx/.xls), PDF, Word (.docx/.doc),
    ODT, RTF, SQL, MDB — individually or inside a ZIP.
    """
    logger.info("scan_file: filename=%s realm=%s", file.filename, realm_name)

    file_bytes = await file.read()

    result = await run_in_threadpool(
        _scan_file_blocking,
        file_bytes,
        file.filename,
        realm_name,
        password,
        db,
    )
    return result
