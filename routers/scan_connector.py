"""
Router: connector-based unstructured scan endpoints

Endpoints:
  POST /scan/start/            – queue a scan for a connector
  GET  /scan/scans/{scan_id}/  – poll scan status
  GET  /scan/files/            – file tree with PII detections for a connector
"""
from __future__ import annotations

import logging
from collections import defaultdict
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from database import get_db
from models import ColumnScan, Scan, ScanAnomaly

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/scan", tags=["Connector Scan"])


# ── Schemas ───────────────────────────────────────────────────────────────────

class ScanStartRequest(BaseModel):
    connector_id: str
    realm_name: Optional[str] = None


# ── Helpers ───────────────────────────────────────────────────────────────────

def _derive_status(scan: Scan) -> str:
    """Derive scan status from existing data (no status column in DB)."""
    if scan.column_scans:
        return "completed"
    # No results yet — if created recently treat as scanning, otherwise failed
    age = (datetime.now(timezone.utc) - scan.created_at.replace(tzinfo=timezone.utc)).total_seconds()
    return "scanning" if age < 300 else "failed"


def _iso(dt: datetime | None) -> str | None:
    if dt is None:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.isoformat()


# ── POST /scan/start/ ─────────────────────────────────────────────────────────

@router.post("/start/")
async def start_scan(body: ScanStartRequest, db: Session = Depends(get_db)):
    """
    Queue a scan for a connector.

    Creates a Scan record with status 'queued'.  Actual connector execution
    (Google Drive, email, etc.) should be triggered here as a background task
    once those connectors are wired up.
    """
    scan = Scan(
        name=f"Connector_Scan_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}",
        connector_id=body.connector_id,
        realm_name=body.realm_name,
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)

    logger.info("start_scan: connector_id=%s scan_id=%s", body.connector_id, scan.id)
    return {
        "scan_id": scan.id,
        "status": "queued",
        "message": "Scan started",
    }


# ── GET /scan/scans/{scan_id}/ ────────────────────────────────────────────────

@router.get("/scans/{scan_id}/")
async def get_scan_status(scan_id: int, db: Session = Depends(get_db)):
    """Return the current status of a scan."""
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail=f"Scan {scan_id} not found")

    return {
        "id": scan.id,
        "status": _derive_status(scan),
        "started_at": _iso(scan.created_at),
        "completed_at": _iso(scan.created_at) if scan.column_scans else None,
    }


# ── GET /scan/files/ ──────────────────────────────────────────────────────────

@router.get("/files/")
async def get_scan_files(connector_id: str, db: Session = Depends(get_db)):
    """
    Return a file tree with PII detections for a given connector.

    Scans belonging to *connector_id* are returned as top-level folders;
    each ColumnScan entry inside becomes a file node with its detections.
    """
    scans = (
        db.query(Scan)
        .filter(Scan.connector_id == connector_id)
        .order_by(Scan.created_at.desc())
        .all()
    )
    if not scans:
        return []

    scan_ids = [s.id for s in scans]
    col_scans = (
        db.query(ColumnScan)
        .filter(ColumnScan.scan_id.in_(scan_ids))
        .all()
    )

    # Pre-fetch anomalies keyed by column_scan_id
    cs_ids = [cs.id for cs in col_scans]
    anomaly_map: dict[int, list[ScanAnomaly]] = defaultdict(list)
    for a in db.query(ScanAnomaly).filter(ScanAnomaly.column_scan_id.in_(cs_ids)).all():
        anomaly_map[a.column_scan_id].append(a)

    # Group column_scans by scan_id
    cs_by_scan: dict[int, list[ColumnScan]] = defaultdict(list)
    for cs in col_scans:
        cs_by_scan[cs.scan_id].append(cs)

    scan_map = {s.id: s for s in scans}
    tree = []

    for scan_id, children in cs_by_scan.items():
        scan = scan_map[scan_id]
        file_nodes = []

        for cs in children:
            detections = []

            if cs.primary_pii_type:
                confidence = (
                    round(cs.primary_pii_match_count / cs.total_rows, 4)
                    if cs.total_rows else 1.0
                )
                detections.append({"type": cs.primary_pii_type, "confidence": confidence})

            for a in anomaly_map.get(cs.id, []):
                detections.append({
                    "type": a.pii_type,
                    "confidence": round(a.confidence_score, 4) if a.confidence_score is not None else None,
                })

            file_nodes.append({
                "name": cs.db_name,
                "type": "file",
                "detections": detections,
            })

        tree.append({
            "name": scan.name,
            "type": "folder",
            "children": file_nodes,
        })

    return tree
