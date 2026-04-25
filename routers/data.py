"""
Router: table data retrieval & ingestion

Endpoints:
  POST /get-table-data       – fetch table rows and send to Vault
  POST /ingest-table-data    – join multiple tables/collections and send batches to Vault
  POST /benchmark-table-data – fetch table rows with timing breakdown
"""

import logging
import time
import uuid
from datetime import date, datetime

import requests as http_requests
from bson.objectid import ObjectId
from fastapi import APIRouter, Header
from fastapi.concurrency import run_in_threadpool
from sqlalchemy import MetaData, select

from db_utils import connect_to_db
from schemas import BenchmarkTableDataRequest, GetTableDataRequest, IngestTableDataRequest

logger = logging.getLogger(__name__)

router = APIRouter(tags=["Data"])


# ── Helpers ───────────────────────────────────────────────────────────────────

def serialize_data(data):
    """Recursively convert dates and UUIDs to strings."""
    if isinstance(data, dict):
        return {k: serialize_data(v) for k, v in data.items()}
    elif isinstance(data, list):
        return [serialize_data(item) for item in data]
    elif isinstance(data, (date, datetime)):
        return data.isoformat()
    elif isinstance(data, uuid.UUID):
        return str(data)
    return data


# ── /get-table-data ───────────────────────────────────────────────────────────

def _fetch_and_send(body: GetTableDataRequest, token: str):
    """Blocking: connect → fetch rows → send to Vault API."""
    engine = connect_to_db(body.db_type, body.db_name, body.user, body.password, body.host, body.port)
    if isinstance(engine, dict) and "error" in engine:
        return engine, 500

    try:
        if body.db_type.startswith("mongodb"):
            collection = engine[body.table_name]
            projection = None
            if body.selected_columns:
                projection = {col: 1 for col in body.selected_columns}
                if "_id" not in body.selected_columns:
                    projection["_id"] = 0
            table_data = list(collection.find({}, projection))
            for doc in table_data:
                if "_id" in doc and isinstance(doc["_id"], ObjectId):
                    doc["_id"] = str(doc["_id"])
        else:
            metadata = MetaData()
            metadata.reflect(bind=engine)
            table = metadata.tables.get(body.table_name)
            if table is None:
                return {"status": "error", "message": f"Table '{body.table_name}' not found"}, 404

            with engine.connect() as conn:
                if body.selected_columns:
                    query = select(*[table.c[c] for c in body.selected_columns])
                else:
                    query = select(table)
                rows = conn.execute(query).fetchall()

            col_names = body.selected_columns if body.selected_columns else list(table.columns.keys())
            table_data = [dict(zip(col_names, row)) for row in rows]

        serialized = serialize_data(table_data)

        ingestion_url = (
            f"https://policyengine.getpatronus.com/api/vault/vaults/{body.vault_name}/records/multiple"
        )
        resp = http_requests.post(
            ingestion_url,
            json={"data": serialized},
            headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
        )

        if resp.status_code != 201:
            return {"status": "error", "message": "Failed to ingest data", "details": resp.text}, 500

        return {
            "status": "success",
            "data": {
                "table": body.table_name,
                "rows": serialized,
                "ingestion_status": resp.json(),
            },
        }, 200

    except Exception as exc:
        logger.exception("get_table_data error")
        return {"status": "error", "message": str(exc)}, 500


@router.post("/get-table-data")
async def get_table_data(
    body: GetTableDataRequest,
    authorization: str = Header(...),
):
    """Fetch all rows from a table/collection and ingest them into Vault."""
    logger.info("get_table_data: db_type=%s table=%s vault=%s", body.db_type, body.table_name, body.vault_name)

    if not authorization.startswith("Bearer "):
        return {"status": "error", "message": "Missing or invalid Authorization header"}

    token = authorization.split(" ", 1)[1]
    result, _ = await run_in_threadpool(_fetch_and_send, body, token)
    return result


# ── /ingest-table-data ────────────────────────────────────────────────────────

def _ingest(body: IngestTableDataRequest, token: str):
    """Blocking: join tables/collections and POST batches to Vault."""
    engine = connect_to_db(body.db_type, body.db_name, body.user, body.password, body.host, body.port)
    if isinstance(engine, dict) and "error" in engine:
        return {"status": "error", "message": engine["error"]}, 422

    try:
        if body.db_type.startswith("mongodb"):
            base_info = body.tables_info[0]
            base_col = engine[base_info.table_name]

            base_proj = {col: 1 for col in base_info.columns} if base_info.columns else None
            if base_proj and body.join_key not in base_proj:
                base_proj[body.join_key] = 1

            base_docs = list(base_col.find({}, base_proj))
            merged = {str(doc.get(body.join_key)): doc for doc in base_docs if body.join_key in doc}

            for info in body.tables_info[1:]:
                col = engine[info.table_name]
                proj = {c: 1 for c in info.columns} if info.columns else None
                if proj:
                    proj[body.join_key] = 1
                for doc in col.find({}, proj):
                    key = str(doc.get(body.join_key))
                    if key in merged:
                        merged[key].update({k: v for k, v in doc.items() if k != body.join_key})

            serialized_data = []
            for doc in merged.values():
                serialized_data.append(
                    {k: str(v) if isinstance(v, ObjectId) else v for k, v in doc.items()}
                )

        else:
            metadata = MetaData()
            metadata.reflect(bind=engine)

            base_info = body.tables_info[0]
            base_table = metadata.tables.get(base_info.table_name)
            if base_table is None:
                return {"status": "error", "message": f"Table '{base_info.table_name}' not found"}, 404

            base_cols = (
                [base_table.c[c] for c in base_info.columns if c in base_table.c]
                if base_info.columns
                else [base_table]
            )
            if not base_cols:
                return {"status": "error", "message": f"No valid columns for '{base_info.table_name}'"}, 400

            query = select(*base_cols).select_from(base_table)

            for info in body.tables_info[1:]:
                t = metadata.tables.get(info.table_name)
                if t is None:
                    return {"status": "error", "message": f"Table '{info.table_name}' not found"}, 404
                cols = [t.c[c] for c in info.columns if c in t.c] if info.columns else [t]
                if body.join_key in t.c:
                    query = query.add_columns(*cols).outerjoin(
                        t, base_table.c[body.join_key] == t.c[body.join_key]
                    )
                else:
                    query = query.add_columns(*cols)

            with engine.connect() as conn:
                rows = conn.execute(query).fetchall()

            unique: dict = {}
            for row in rows:
                row_dict = {k: serialize_data(v) for k, v in row._mapping.items()}
                jk = row_dict.get(body.join_key)
                if jk is not None:
                    row_dict["_id"] = str(jk)
                    unique[jk] = serialize_data(row_dict)
            serialized_data = list(unique.values())

        # Batch the data
        columns_count = len(serialized_data[0].keys()) if serialized_data else 1
        max_batch = 65535 // max(columns_count, 1)

        ingestion_url = (
            f"https://policyengine.getpatronus.com/api/vault/vaults/{body.vault_name}/records/multiple"
        )
        headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}

        for i in range(0, len(serialized_data), max_batch):
            batch = serialized_data[i : i + max_batch]
            resp = http_requests.post(ingestion_url, json={"data": batch}, headers=headers)
            if resp.status_code != 201:
                return {"status": "error", "message": "Failed to ingest data", "details": resp.text}, 422

        return {"status": "success", "message": "All batches ingested successfully"}, 200

    except Exception as exc:
        logger.exception("ingest_table_data error")
        return {"status": "error", "message": str(exc)}, 400


@router.post("/ingest-table-data")
async def ingest_table_data(
    body: IngestTableDataRequest,
    authorization: str = Header(...),
):
    """Join multiple tables/collections and ingest the merged data into Vault in batches."""
    logger.info("ingest_table_data: db_type=%s vault=%s", body.db_type, body.vault_name)

    if not authorization.startswith("Bearer "):
        return {"status": "error", "message": "Missing or invalid Authorization header"}

    token = authorization.split(" ", 1)[1]
    result, _ = await run_in_threadpool(_ingest, body, token)
    return result


# ── /benchmark-table-data ─────────────────────────────────────────────────────

def _benchmark(body: BenchmarkTableDataRequest):
    """Blocking: fetch table data and record timing per step."""
    t0 = time.time()
    engine = connect_to_db(body.db_type, body.db_name, body.user, body.password, body.host, body.port)
    if isinstance(engine, dict) and "error" in engine:
        return {"status": "error", "message": engine["error"]}, 500
    db_connection_time = time.time() - t0

    try:
        t0 = time.time()
        metadata = MetaData()
        metadata.reflect(bind=engine)
        reflection_time = time.time() - t0

        t0 = time.time()
        table = metadata.tables.get(body.table_name)
        if table is None:
            return {"status": "error", "message": f"Table '{body.table_name}' not found"}, 404
        table_access_time = time.time() - t0

        with engine.connect() as conn:
            t0 = time.time()
            if body.selected_columns:
                query = select(*[table.c[c] for c in body.selected_columns])
            else:
                query = select(table)
            rows = conn.execute(query).fetchall()
            query_time = time.time() - t0

        t0 = time.time()
        col_names = body.selected_columns if body.selected_columns else list(table.columns.keys())
        data = [dict(zip(col_names, row)) for row in rows]
        processing_time = time.time() - t0

        total = db_connection_time + reflection_time + table_access_time + query_time + processing_time

        return {
            "status": "success",
            "data": {
                "table": body.table_name,
                "rows": data,
                "benchmark": {
                    "db_connection_time": db_connection_time,
                    "reflection_time": reflection_time,
                    "table_access_time": table_access_time,
                    "query_execution_time": query_time,
                    "data_processing_time": processing_time,
                    "total_time": total,
                },
            },
        }, 200

    except Exception as exc:
        logger.exception("benchmark_table_data error")
        return {"status": "error", "message": str(exc)}, 500


@router.post("/benchmark-table-data")
async def benchmark_table_data(body: BenchmarkTableDataRequest):
    """Fetch table rows and return detailed per-step timing breakdown."""
    logger.info("benchmark_table_data: db_type=%s table=%s", body.db_type, body.table_name)
    result, _ = await run_in_threadpool(_benchmark, body)
    return result
