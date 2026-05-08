"""
Pydantic schemas for request validation.

FastAPI uses these to:
  - validate incoming JSON bodies
  - auto-generate the /docs Swagger UI
"""

from typing import List, Optional
from pydantic import BaseModel


# ── Shared DB-connection fields ───────────────────────────────────────────────

class DBConnectionBase(BaseModel):
    db_type: str
    db_name: str
    user: Optional[str] = None
    password: Optional[str] = None
    host: Optional[str] = "localhost"
    port: Optional[int] = None


# ── /check-connection ─────────────────────────────────────────────────────────

class CheckConnectionRequest(DBConnectionBase):
    pass


# ── /get-schema ───────────────────────────────────────────────────────────────

class GetSchemaRequest(DBConnectionBase):
    scan_type: Optional[str] = "metadata"


# ── /get-table-data ───────────────────────────────────────────────────────────

class GetTableDataRequest(DBConnectionBase):
    table_name: str
    selected_columns: Optional[List[str]] = []
    vault_name: str


# ── /benchmark-table-data ─────────────────────────────────────────────────────

class BenchmarkTableDataRequest(DBConnectionBase):
    table_name: str
    selected_columns: Optional[List[str]] = []


# ── /ingest-table-data ────────────────────────────────────────────────────────

class TableInfo(BaseModel):
    table_name: str
    columns: Optional[List[str]] = []


class IngestTableDataRequest(DBConnectionBase):
    tables_info: List[TableInfo]
    join_key: Optional[str] = "id"
    vault_name: str


# ── /scan-database ────────────────────────────────────────────────────────────

class ScanDatabaseRequest(DBConnectionBase):
    connector_id: str
    pii_ids: Optional[List[str]] = []
    scan_name: Optional[str] = None
    realm_name: Optional[str] = None


# ── /redact ───────────────────────────────────────────────────────────────────

class RedactRequest(BaseModel):
    scan_id: int
    filenames: List[str]
    pii_types: List[str]
    redaction_type: Optional[str] = "contextual"   # full | partial | contextual | mask


# ── Standardised API response wrapper ────────────────────────────────────────

class APIResponse(BaseModel):
    status: str
    data: Optional[dict] = None
    message: Optional[str] = None
