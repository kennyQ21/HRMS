"""
Router: dashboard summary

Endpoint:
  GET /data-discovery/dashboard/summary
"""
from __future__ import annotations

import logging
from collections import defaultdict
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from database import get_db
from models import ColumnScan, Scan, ScanAnomaly

logger = logging.getLogger(__name__)

router = APIRouter(tags=["Dashboard"])

# PII types that count as high-risk findings
_HIGH_RISK_TYPES = {"aadhaar", "pan", "credit_card", "cvv", "in_pan", "in_aadhaar", "in_voter", "voter_id"}

_UNSTRUCTURED_CONNECTOR = "file_upload"


def _iso_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _is_unstructured(connector_id: str) -> bool:
    return connector_id == _UNSTRUCTURED_CONNECTOR or connector_id.endswith("_parser")


@router.get("/data-discovery/dashboard/summary")
async def dashboard_summary(
    realm_name: Optional[str] = None,
    from_date: Optional[str] = None,
    to_date: Optional[str] = None,
    db: Session = Depends(get_db),
):
    """
    Aggregated dashboard summary across all scans.

    Query params:
        realm_name  – filter to a specific tenant
        from_date   – ISO-8601 start of window (inclusive)
        to_date     – ISO-8601 end of window (inclusive)
    """
    # ── Load scans ────────────────────────────────────────────────────────────
    q = db.query(Scan)
    if realm_name:
        q = q.filter(Scan.realm_name == realm_name)
    if from_date:
        q = q.filter(Scan.created_at >= from_date)
    if to_date:
        q = q.filter(Scan.created_at <= to_date)

    scans = q.order_by(Scan.created_at.desc()).all()

    structured_ids, unstructured_ids = [], []
    status_counts: dict[str, int] = defaultdict(int)

    for s in scans:
        if _is_unstructured(s.connector_id):
            unstructured_ids.append(s.id)
        else:
            structured_ids.append(s.id)
        status = "completed" if s.column_scans else "queued"
        status_counts[status] += 1

    all_scan_ids = structured_ids + unstructured_ids

    # ── Load column scans ─────────────────────────────────────────────────────
    col_scans = (
        db.query(ColumnScan).filter(ColumnScan.scan_id.in_(all_scan_ids)).all()
        if all_scan_ids else []
    )

    cs_by_scan: dict[int, list[ColumnScan]] = defaultdict(list)
    for cs in col_scans:
        cs_by_scan[cs.scan_id].append(cs)

    # ── Load anomalies ────────────────────────────────────────────────────────
    cs_ids = [cs.id for cs in col_scans]
    anomalies = (
        db.query(ScanAnomaly).filter(ScanAnomaly.column_scan_id.in_(cs_ids)).all()
        if cs_ids else []
    )

    anomaly_map: dict[int, list[ScanAnomaly]] = defaultdict(list)
    for a in anomalies:
        anomaly_map[a.column_scan_id].append(a)

    # ── Aggregate metrics ─────────────────────────────────────────────────────
    def _agg(scan_ids: list[int]):
        flagged = pii_matches = high_risk = redaction_eligible = 0
        unique_types: set[str] = set()
        pii_type_counts: dict[str, int] = defaultdict(int)

        for sid in scan_ids:
            for cs in cs_by_scan.get(sid, []):
                has_pii = bool(cs.primary_pii_type)
                if has_pii:
                    flagged += 1
                    pii_matches += cs.primary_pii_match_count or 0
                    unique_types.add(cs.primary_pii_type)
                    pii_type_counts[cs.primary_pii_type] += cs.primary_pii_match_count or 0
                    if cs.primary_pii_type in _HIGH_RISK_TYPES:
                        high_risk += 1

                for a in anomaly_map.get(cs.id, []):
                    pii_matches += a.match_count or 0
                    unique_types.add(a.pii_type)
                    pii_type_counts[a.pii_type] += a.match_count or 0
                    if a.pii_type in _HIGH_RISK_TYPES and not has_pii:
                        high_risk += 1

                if cs.table_name == "image":
                    redaction_eligible += 1

        return flagged, pii_matches, high_risk, redaction_eligible, unique_types, pii_type_counts

    s_flag, s_pii, s_risk, s_redact, s_types, s_type_counts = _agg(structured_ids)
    u_flag, u_pii, u_risk, u_redact, u_types, u_type_counts = _agg(unstructured_ids)

    # Merge top PII type counts across both
    all_type_counts: dict[str, int] = defaultdict(int)
    for t, c in s_type_counts.items():
        all_type_counts[t] += c
    for t, c in u_type_counts.items():
        all_type_counts[t] += c

    top_pii = sorted(
        [{"type": t, "count": c} for t, c in all_type_counts.items()],
        key=lambda x: x["count"],
        reverse=True,
    )[:10]

    # ── Recent scans ──────────────────────────────────────────────────────────
    recent_scans = []
    for s in scans[:10]:
        cs_list = cs_by_scan.get(s.id, [])
        scan_flags = sum(1 for cs in cs_list if cs.primary_pii_type)
        scan_pii = sum((cs.primary_pii_match_count or 0) for cs in cs_list)
        for cs in cs_list:
            scan_pii += sum((a.match_count or 0) for a in anomaly_map.get(cs.id, []))

        dt = s.created_at
        if dt and dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)

        recent_scans.append({
            "scan_id": s.id,
            "scan_name": s.name,
            "mode": "unstructured" if _is_unstructured(s.connector_id) else "structured",
            "status": "completed" if cs_list else "queued",
            "created_at": dt.isoformat() if dt else None,
            "flagged_assets": scan_flags,
            "pii_matches": scan_pii,
        })

    # ── Build response ────────────────────────────────────────────────────────
    window_from = from_date or (scans[-1].created_at.isoformat() if scans else None)
    window_to = to_date or _iso_now()

    return {
        "generated_at": _iso_now(),
        "realm_name": realm_name,
        "window": {"from": window_from, "to": window_to},
        "scan_counts": {
            "all": len(scans),
            "structured": len(structured_ids),
            "unstructured": len(unstructured_ids),
        },
        "status_counts": {
            "queued": status_counts.get("queued", 0),
            "scanning": status_counts.get("scanning", 0),
            "completed": status_counts.get("completed", 0),
            "failed": status_counts.get("failed", 0),
        },
        "findings": {
            "flagged_assets": {
                "all": s_flag + u_flag,
                "structured_columns": s_flag,
                "unstructured_files": u_flag,
            },
            "pii_matches": {
                "all": s_pii + u_pii,
                "structured": s_pii,
                "unstructured": u_pii,
            },
            "unique_pii_types": {
                "all": len(s_types | u_types),
                "structured": len(s_types),
                "unstructured": len(u_types),
            },
            "high_risk": {
                "all": s_risk + u_risk,
                "structured_anomalies": s_risk,
                "unstructured_files": u_risk,
            },
            "redaction_eligible_files": s_redact + u_redact,
        },
        "top_pii_types": top_pii,
        "recent_scans": recent_scans,
    }
