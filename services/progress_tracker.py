from __future__ import annotations

from services.job_store import update_job

STAGE_PROGRESS = {
    "INITIALIZING": 2,
    "PARSING": 10,
    "OCR_PROCESSING": 35,
    "DETECTING_PII": 65,
    "ENTITY_RESOLUTION": 85,
    "PERSISTING_RESULTS": 95,
    "COMPLETED": 100,
}


def update_stage(job_id: str, stage: str, current_file: str | None = None) -> None:
    payload = {
        "current_stage": stage,
        "progress": STAGE_PROGRESS.get(stage, 0),
    }
    if current_file is not None:
        payload["current_file"] = current_file
    update_job(job_id, **payload)
