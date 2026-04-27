"""
Router: PII scanning of databases

Endpoints:
  POST /scan-database            – scan a DB for PII and store results
  GET  /get-scan-results/{id}    – get column-level PII results for a scan
  GET  /get-scans                – list all scans (filterable by realm_name)
"""

import logging
from collections import defaultdict
from typing import List, Optional

from fastapi import APIRouter, Depends
from fastapi.concurrency import run_in_threadpool
from sqlalchemy import MetaData, select
from sqlalchemy.orm import Session

from constants import PII_TYPES, PIIType
from database import get_db
from db_utils import connect_to_db
from models import ColumnScan, PIILocation, Scan, ScanAnomaly
from schemas import ScanDatabaseRequest
from services.pii_service import detect_pii, select_primary_pii

logger = logging.getLogger(__name__)

router = APIRouter(tags=["Scanning"])


# ── PII helpers ───────────────────────────────────────────────────────────────

def process_column_data(
    session: Session,
    scan: Scan,
    connector_id: str,
    db_name: str,
    table_name: str,
    column_name: str,
    values: list,
    pii_types: List[PIIType],
):
    """
    Scan column values for PII using the regex layer only (use_nlp=False).

    Rationale: column values are short, structured strings.  Running a full
    spaCy NLP model over thousands of individual cell values adds latency
    with minimal recall gain.  The NER layer is reserved for free-form text
    (documents, OCR output) via process_document_content below.
    """
    try:
        pii_matches: dict = defaultdict(int)
        total_rows = len(values)
        primary_pii = (None, 0)  # (pii_id, match_count)

        for value in values:
            if value is None:
                continue
            # Regex-only: fast, deterministic, correct for structured values
            result = detect_pii(str(value), use_nlp=False)
            for pii_id, count in result.counts.items():
                # Filter to only the pii_types selected for this scan
                selected_ids = {p["id"] for p in pii_types}
                if pii_id in selected_ids:
                    pii_matches[pii_id] += count

        # Primary PII = type with >50% match rate and highest count
        for pii_id, match_count in pii_matches.items():
            if total_rows and match_count / total_rows > 0.5 and match_count > primary_pii[1]:
                primary_pii = (pii_id, match_count)

        column_scan = ColumnScan(
            db_name=db_name,
            table_name=table_name,
            column_name=column_name,
            total_rows=total_rows,
            primary_pii_type=primary_pii[0],
            primary_pii_match_count=primary_pii[1],
            scan=scan,
        )
        session.add(column_scan)
        session.flush()

        for pii_id, match_count in pii_matches.items():
            if pii_id != primary_pii[0] and match_count > 0:
                session.add(
                    ScanAnomaly(
                        pii_type=pii_id,
                        match_count=match_count,
                        confidence_score=match_count / total_rows if total_rows else None,
                        column_scan=column_scan,
                    )
                )
    except Exception as exc:
        logger.error("Error processing column %s: %s", column_name, exc)
        raise


def process_document_content(
    session: Session,
    scan: Scan,
    connector_id: str,
    db_name: str,
    text_content: str,
    pii_types: List[PIIType],
):
    """
    Scan raw document / OCR text for PII using the FULL hybrid pipeline.

    Uses both regex (structured patterns) AND Presidio NER (contextual
    entities like PERSON, LOCATION, ORGANIZATION) for maximum recall.
    This is the right place to run NLP because document text is:
      - long enough for context to matter
      - already clean (post-OCR or extracted text)
      - processed once per file, so the NLP overhead is acceptable
    """
    selected_ids = {p["id"] for p in pii_types}

    # Full hybrid pipeline: regex + Presidio NER
    result = detect_pii(text_content, use_nlp=True)

    filtered_matches = [
        match for match in result.matches
        if not selected_ids or match.pii_type in selected_ids
    ]

    # Filter to selected PII types + build counts
    pii_matches: dict = defaultdict(int)
    for match in filtered_matches:
        pii_matches[match.pii_type] += 1

    # Log what each layer found
    regex_types  = {m.pii_type for m in result.matches if m.source == "regex"}
    nlp_types    = {m.pii_type for m in result.matches if m.source == "presidio"}
    logger.info(
        "document scan — regex: %s | presidio: %s | merged total: %d matches",
        sorted(regex_types), sorted(nlp_types), len(result.matches),
    )

    primary_type, primary_count, _ = select_primary_pii(filtered_matches, allowed_types=selected_ids)

    column_scan = ColumnScan(
        db_name=db_name,
        table_name="document",
        column_name="content",
        total_rows=1,
        primary_pii_type=primary_type,
        primary_pii_match_count=primary_count,
        scan=scan,
    )
    session.add(column_scan)
    session.flush()

    for pii_id, count in pii_matches.items():
        if pii_id != primary_type and count > 0:
            confidence = min(count / max(len(text_content.split()), 1), 1.0)
            session.add(
                ScanAnomaly(
                    pii_type=pii_id,
                    match_count=count,
                    confidence_score=round(confidence, 4),
                    column_scan=column_scan,
                )
            )

    return column_scan


def process_image_content(
    session: Session,
    scan: Scan,
    source_file: str,
    best_text: str,
    lines: list,
    pii_types: List[PIIType],
):
    """
    Process OCR output from an image file.

    *best_text* — high-quality text from the multi-variant OCR pass, used for
    PII detection.

    *lines* — list of (text, bbox) pairs from a raw-image OCR pass where bbox
    is [[x1,y1],[x2,y1],[x2,y2],[x1,y2]] in original image pixels. Used only
    for bounding-box lookup; not for detection.

    Bbox matching is done by searching each PII match value inside the raw OCR
    line texts (substring search, case-insensitive). This is robust to the two
    OCR passes producing slightly different tokenisation.
    """
    import json

    selected_ids = {p["id"] for p in pii_types}

    result = detect_pii(best_text, use_nlp=True)
    filtered = [m for m in result.matches if not selected_ids or m.pii_type in selected_ids]

    pii_counts: dict = defaultdict(int)
    for m in filtered:
        pii_counts[m.pii_type] += 1

    primary_type, primary_count, _ = select_primary_pii(filtered, allowed_types=selected_ids)

    column_scan = ColumnScan(
        db_name=source_file,
        table_name="image",
        column_name="content",
        total_rows=1,
        primary_pii_type=primary_type,
        primary_pii_match_count=primary_count,
        scan=scan,
    )
    session.add(column_scan)
    session.flush()

    for pii_id, count in pii_counts.items():
        if pii_id != primary_type and count > 0:
            confidence = min(count / max(len(best_text.split()), 1), 1.0)
            session.add(ScanAnomaly(
                pii_type=pii_id,
                match_count=count,
                confidence_score=round(confidence, 4),
                column_scan=column_scan,
            ))

    # Scan each raw OCR line individually with regex to find ALL PII occurrences.
    # This correctly handles: duplicate values (same Aadhaar twice), multiple
    # PII types on different lines, and values that were deduplicated in the
    # full-text pass but appear on distinct lines with distinct bboxes.
    for line_text, bbox in lines:
        line_result = detect_pii(line_text, use_nlp=False)
        for m in line_result.matches:
            if not selected_ids or m.pii_type in selected_ids:
                session.add(PIILocation(
                    scan_id=scan.id,
                    column_scan_id=column_scan.id,
                    pii_type=m.pii_type,
                    value=m.value,
                    bbox=json.dumps(bbox),
                    source_file=source_file,
                ))

    return column_scan


# ── /scan-database ────────────────────────────────────────────────────────────

def _run_scan(body: ScanDatabaseRequest, db: Session):
    """Blocking: connect to target DB, scan all columns, persist results."""
    selected_pii = [p for p in PII_TYPES if p["id"] in body.pii_ids] if body.pii_ids else PII_TYPES

    engine = connect_to_db(body.db_type, body.db_name, body.user, body.password, body.host, body.port)
    if isinstance(engine, dict) and "error" in engine:
        return {"status": "error", "message": engine["error"]}, 500

    try:
        # Delete old scans for this connector
        for old in db.query(Scan).filter_by(connector_id=body.connector_id).all():
            db.delete(old)
        db.commit()

        scan = Scan(name=body.scan_name, connector_id=body.connector_id, realm_name=body.realm_name)
        db.add(scan)
        db.flush()

        if body.db_type.startswith("mongodb"):
            for col_name in engine.list_collection_names():
                collection = engine[col_name]
                sample_docs = list(collection.find().limit(1000))
                fields: set = set()
                for doc in sample_docs:
                    fields.update(doc.keys())
                for field in fields:
                    values = [doc.get(field) for doc in sample_docs if field in doc]
                    process_column_data(db, scan, body.connector_id, body.db_name, col_name, field, values, selected_pii)
        else:
            metadata = MetaData()
            metadata.reflect(bind=engine)
            for table_name, table in metadata.tables.items():
                with engine.connect() as conn:
                    rows = [dict(r._mapping) for r in conn.execute(select(table).limit(1000))]
                for col in table.columns:
                    values = [r.get(col.name) for r in rows]
                    process_column_data(db, scan, body.connector_id, body.db_name, table_name, col.name, values, selected_pii)

        db.commit()
        logger.info("Scan completed: scan_id=%s connector_id=%s", scan.id, body.connector_id)
        return {"status": "success", "data": {"scan_id": scan.id}}, 200

    except Exception as exc:
        db.rollback()
        logger.exception("scan_database error")
        return {"status": "error", "message": str(exc)}, 500


@router.post("/scan-database")
async def scan_database(body: ScanDatabaseRequest, db: Session = Depends(get_db)):
    """Scan every column/field of a database for PII and persist the results."""
    logger.info("scan_database: connector_id=%s db_type=%s", body.connector_id, body.db_type)

    if not all([body.db_type, body.db_name, body.connector_id]):
        return {"status": "error", "message": "Missing required parameters"}

    result, _ = await run_in_threadpool(_run_scan, body, db)
    return result


# ── /get-scan-results/{scan_id} ───────────────────────────────────────────────

@router.get("/get-scan-results/{scan_id}")
async def get_scan_results(scan_id: int, db: Session = Depends(get_db)):
    """Return column-level PII results and anomalies for a specific scan."""
    logger.info("get_scan_results: scan_id=%s", scan_id)

    try:
        scan = db.get(Scan, scan_id)
        if scan is None:
            return {"status": "error", "message": f"Scan {scan_id} not found"}

        pii_type_totals: dict = defaultdict(int)
        columns = []

        for cs in scan.column_scans:
            if cs.primary_pii_type and cs.primary_pii_match_count:
                pii_type_totals[cs.primary_pii_type] += cs.primary_pii_match_count

            anomalies = []
            for anomaly in cs.anomalies:
                pii_type_totals[anomaly.pii_type] += anomaly.match_count
                anomalies.append(
                    {
                        "pii_type": anomaly.pii_type,
                        "match_count": anomaly.match_count,
                        "confidence_score": round(anomaly.confidence_score, 3) if anomaly.confidence_score is not None else None,
                    }
                )

            columns.append(
                {
                    "id": cs.id,
                    "db_name": cs.db_name,
                    "table_name": cs.table_name,
                    "column_name": cs.column_name,
                    "total_rows": cs.total_rows,
                    "primary_pii_type": cs.primary_pii_type,
                    "primary_pii_match_count": cs.primary_pii_match_count,
                    "anomalies": anomalies,
                }
            )

        return {
            "status": "success",
            "data": {
                "pii_type_totals": dict(pii_type_totals),
                "scan_result": {
                    "scan_id": scan.id,
                    "scan_name": scan.name,
                    "connector_id": scan.connector_id,
                    "created_at": scan.created_at.isoformat() if scan.created_at else None,
                    "columns": columns,
                },
            },
        }

    except Exception as exc:
        logger.exception("get_scan_results error")
        return {"status": "error", "message": str(exc)}


# ── /get-scans ────────────────────────────────────────────────────────────────

@router.get("/get-scans")
async def get_scans(realm_name: Optional[str] = None, db: Session = Depends(get_db)):
    """List all scans, optionally filtered by realm_name."""
    logger.info("get_scans: realm_name=%s", realm_name)

    try:
        query = db.query(Scan).order_by(Scan.created_at.desc())
        if realm_name:
            query = query.filter_by(realm_name=realm_name)

        scans = query.all()
        scans_list = [
            {
                "id": s.id,
                "name": s.name,
                "connector_id": s.connector_id,
                "realm_name": s.realm_name,
                "created_at": s.created_at.isoformat() if s.created_at else None,
                "column_count": len(s.column_scans),
            }
            for s in scans
        ]

        return {"status": "success", "data": {"scans": scans_list, "total": len(scans_list)}}

    except Exception as exc:
        logger.exception("get_scans error")
        return {"status": "error", "message": str(exc)}
