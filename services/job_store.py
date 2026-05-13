from __future__ import annotations

from datetime import datetime, timezone
from threading import Lock
from typing import Dict, Optional
from uuid import uuid4

JOB_STORE: Dict[str, dict] = {}
JOB_LOCK = Lock()


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def create_job(filename: str) -> str:
    job_id = f"scan_{uuid4().hex[:12]}"
    state = {
        "job_id": job_id,
        "status": "QUEUED",
        "progress": 0,
        "current_stage": "INITIALIZING",
        "total_files": 1,
        "processed_files": 0,
        "skipped_files": 0,
        "failed_files": 0,
        "current_file": filename,
        "total_entities": 0,
        "distribution": {},
        "summary": {
            "total_entities": 0,
            "unique_types": 0,
            "risk_score": 0.0,
            "risk_level": "LOW",
        },
        "files": [],
        "detailed_results": [],
        "skipped": [],
        "started_at": _utc_now_iso(),
        "completed_at": None,
        "errors": [],
        "result": None,
    }
    with JOB_LOCK:
        JOB_STORE[job_id] = state
    return job_id


def update_job(job_id: str, **kwargs) -> Optional[dict]:
    with JOB_LOCK:
        job = JOB_STORE.get(job_id)
        if not job:
            return None
        job.update(kwargs)
        return dict(job)


def get_job(job_id: str) -> Optional[dict]:
    with JOB_LOCK:
        job = JOB_STORE.get(job_id)
        if not job:
            return None
        return dict(job)


def increment_entity_count(job_id: str, pii_type: str) -> Optional[dict]:
    with JOB_LOCK:
        job = JOB_STORE.get(job_id)
        if not job:
            return None
        distribution = dict(job.get("distribution", {}))
        distribution[pii_type] = distribution.get(pii_type, 0) + 1
        job["distribution"] = distribution
        job["total_entities"] = int(job.get("total_entities", 0)) + 1
        return dict(job)


def complete_job(job_id: str, result: Optional[dict] = None) -> Optional[dict]:
    with JOB_LOCK:
        job = JOB_STORE.get(job_id)
        if not job:
            return None
        job["status"] = "COMPLETED"
        job["progress"] = 100
        job["current_stage"] = "COMPLETED"
        job["current_file"] = None
        job["completed_at"] = _utc_now_iso()
        if result is not None:
            job["result"] = result
        return dict(job)


def fail_job(job_id: str, error: str) -> Optional[dict]:
    with JOB_LOCK:
        job = JOB_STORE.get(job_id)
        if not job:
            return None
        job["status"] = "FAILED"
        job["current_stage"] = "FAILED"
        job["completed_at"] = _utc_now_iso()
        errors = list(job.get("errors", []))
        errors.append(error)
        job["errors"] = errors
        return dict(job)
