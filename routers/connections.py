"""
Router: connections & schema discovery

Endpoints:
  POST /check-connection   – test a DB connection
  POST /get-schema         – return column PII metadata for a DB
  GET  /get-pii-types      – return all known PII type definitions
"""

import logging

from fastapi import APIRouter
from fastapi.concurrency import run_in_threadpool

from constants import PII_TYPES
from db_utils import connect_to_db, scan_columns_for_pii_sql, scan_columns_for_pii_mongo
from schemas import CheckConnectionRequest, GetSchemaRequest

logger = logging.getLogger(__name__)

router = APIRouter(tags=["Connections & Schema"])


# ── /check-connection ─────────────────────────────────────────────────────────

@router.post("/check-connection")
async def check_connection(body: CheckConnectionRequest):
    """Test whether a database connection can be established."""
    logger.info("check_connection called: db_type=%s db_name=%s", body.db_type, body.db_name)

    if not body.db_type or not body.db_name:
        return {"status": "error", "message": "Missing database type or database name"}, 400

    engine = await run_in_threadpool(
        connect_to_db, body.db_type, body.db_name, body.user, body.password, body.host, body.port
    )

    if isinstance(engine, dict) and "error" in engine:
        return {
            "status": "error",
            "message": "Cannot establish connection",
            "details": engine["error"],
        }

    logger.info("check_connection success: db_type=%s", body.db_type)
    return {"status": "success", "message": "Connection successful"}


# ── /get-schema ───────────────────────────────────────────────────────────────

@router.post("/get-schema")
async def get_schema(body: GetSchemaRequest):
    """Return the PII-annotated schema for a database."""
    logger.info("get_schema called: db_type=%s db_name=%s", body.db_type, body.db_name)

    if not body.db_type or not body.db_name:
        return {"status": "error", "message": "Missing database type or database name"}

    engine = await run_in_threadpool(
        connect_to_db, body.db_type, body.db_name, body.user, body.password, body.host, body.port
    )

    if isinstance(engine, dict) and "error" in engine:
        return {"status": "error", "message": engine["error"]}

    if body.db_type in ("postgres", "oracle"):
        schema_info = await run_in_threadpool(scan_columns_for_pii_sql, engine, body.scan_type)
    elif body.db_type.startswith("mongodb"):
        schema_info = await run_in_threadpool(scan_columns_for_pii_mongo, engine, body.scan_type)
    else:
        return {"status": "error", "message": f"Unsupported db_type for schema scan: {body.db_type}"}

    return {"status": "success", "data": schema_info}


# ── /get-pii-types ────────────────────────────────────────────────────────────

@router.get("/get-pii-types")
async def get_pii_types():
    """Return all PII type definitions with their regex patterns and metadata."""
    logger.info("get_pii_types called")

    serialized = [
        {
            "id": pii["id"],
            "name": pii["name"],
            "description": pii["description"],
            "category": pii["category"].value,
            "sensitivity": pii["sensitivity"].value,
        }
        for pii in PII_TYPES
    ]

    return {"status": "success", "data": serialized}
