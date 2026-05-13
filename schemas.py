"""
Pydantic schemas for request validation.

FastAPI uses these to:
  - validate incoming JSON bodies
  - auto-generate the /docs Swagger UI
"""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


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


class ScanJobResponse(BaseModel):
    job_id: str
    status: str


class SummaryModel(BaseModel):
    total_entities: int = 0
    unique_types: int = 0
    risk_score: float = 0.0
    risk_level: str = "LOW"


class ProcessingMetricsModel(BaseModel):
    total_ms: float = 0.0
    ocr_ms: float = 0.0
    detection_ms: float = 0.0
    resolution_ms: float = 0.0


class FileSummaryModel(BaseModel):
    file_name: str
    status: str
    entities: int = 0
    risk_level: str = "LOW"
    distribution: Dict[str, int] = Field(default_factory=dict)
    processing_metrics: ProcessingMetricsModel


class DetailedResultModel(BaseModel):
    file_name: str
    entities: List[Dict[str, Any]] = Field(default_factory=list)


class ScanStatusResponse(BaseModel):
    job_id: str
    status: str
    progress: int
    current_stage: str
    total_files: int = 0
    processed_files: int = 0
    skipped_files: int = 0
    failed_files: int = 0
    current_file: Optional[str] = None
    started_at: Optional[str] = None
    completed_at: Optional[str] = None
    elapsed_seconds: int = 0
    summary: SummaryModel
    distribution: Dict[str, int] = Field(default_factory=dict)
    files: List[FileSummaryModel] = Field(default_factory=list)
    detailed_results: List[DetailedResultModel] = Field(default_factory=list)
    skipped: List[str] = Field(default_factory=list)
    errors: List[str] = Field(default_factory=list)
