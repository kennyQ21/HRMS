# Vault Migration Service

Flask service for:
- connecting to source databases,
- detecting/scanning PII in databases and files,
- storing scan results in its own metadata DB,
- ingesting selected records into Patronus Vault.

This repository currently exposes HTTP APIs for schema inspection, PII scanning, scan history retrieval, file scanning, and data ingestion workflows.

## Table Of Contents
1. [What This Service Does](#what-this-service-does)
2. [High-Level Architecture](#high-level-architecture)
3. [Repository Structure](#repository-structure)
4. [Supported Sources And Formats](#supported-sources-and-formats)
5. [PII Model And Detection Logic](#pii-model-and-detection-logic)
6. [Data Model (Internal Scan DB)](#data-model-internal-scan-db)
7. [Configuration](#configuration)
8. [Run Locally (Poetry)](#run-locally-poetry)
9. [Run With Docker Compose](#run-with-docker-compose)
10. [API Reference](#api-reference)
11. [Known Caveats](#known-caveats)
12. [Troubleshooting](#troubleshooting)

## What This Service Does
- Validates source DB connectivity (`/check-connection`).
- Inspects schema/fields and estimates PII confidence (`/get-schema`).
- Scans database rows/documents and persists PII findings (`/scan-database`).
- Scans uploaded files (including `.zip`) for PII and persists findings (`/scan-file`).
- Returns scan summaries and detailed per-column anomalies (`/get-scans`, `/get-scan-results/<id>`).
- Ingests source records to Patronus Vault APIs (`/get-table-data`, `/ingest-table-data`).

## High-Level Architecture
1. API layer in `app.py` handles all routes.
2. `db_utils.py` builds SQLAlchemy/PyMongo connections and performs schema-level PII heuristics.
3. `constants.py` defines regex-driven PII types (email, phone, Aadhaar, PAN, etc.).
4. `scan_database` and `scan_file` convert raw values/content into `Scan`, `ColumnScan`, `ScanAnomaly` records.
5. Flask-SQLAlchemy models in `models.py` persist scan outcomes to:
   - SQLite (`pii_scans.db`) in development.
   - Postgres in production (`Config` + env vars).

## Repository Structure
```text
.
├── app.py                         # Main Flask app and all API routes
├── db_utils.py                    # DB connectors + schema/field PII heuristics
├── constants.py                   # PII type catalog + regex patterns
├── models.py                      # Scan, ColumnScan, ScanAnomaly ORM models
├── config.py                      # Environment-specific Flask/DB config
├── extensions.py                  # SQLAlchemy + Flask-Migrate init objects
├── connectors.py                  # Google Drive + Email connector classes (not route-wired)
├── parsers/
│   ├── structured/
│   │   ├── csv_parser.py          # CSV parser
│   │   └── excel_parser.py        # Excel parser (.xls/.xlsx)
│   └── unstructured/
│       ├── document_parser.py     # DOC/DOCX/ODT/RTF + PDF parser/OCR
│       ├── sql_parser.py          # SQL file parser (tables/procedures/content)
│       └── access_parser.py       # MS Access .mdb parser
├── migrations/                    # Alembic migration scripts/config
├── Dockerfile
├── docker-compose.yml
├── pyproject.toml                 # Poetry dependencies
├── pii_scans.db                   # Local SQLite DB (development)
└── tests/                         # Standalone test scripts (OCR, PDF parsing, LLM baseline)
```

## Supported Sources And Formats

### Databases (`db_type`)
- `postgres`
- `mysql`
- `sqlite`
- `mssql`
- `oracle`
- `mariadb`
- `mongodb_standard`
- `mongodb_srv`

Notes:
- `/get-schema` currently branches only for `postgres`, `oracle`, and MongoDB variants.
- `/scan-database` works for SQLAlchemy-supported SQL DBs and MongoDB.

### Files (`/scan-file`)
- Structured: `.csv`, `.xls`, `.xlsx`
- Unstructured: `.doc`, `.docx`, `.odt`, `.rtf`, `.pdf`, `.sql`, `.mdb`
- Archive: `.zip` (recursively scans supported files inside archive)
- Password support:
  - password-protected ZIPs (via form field `password`)
  - encrypted PDFs (via form field `password`)

## PII Model And Detection Logic

### Built-In PII Types
Defined in `constants.py` with category + sensitivity + regex:
- `email`
- `phone`
- `dob`
- `pan`
- `aadhaar`
- `credit_card`
- `expiry`
- `cvv`
- `address`

### Schema Heuristic Scan (`/get-schema`)
In `db_utils.py`:
- `metadata` mode: checks column/field names against PII-oriented regex rules.
- `dual` mode: metadata checks + sample-value regex checks.
- Confidence output:
  - `0`: no signal
  - `0.5`: either metadata or sample-data signaled
  - `1.0`: both metadata and sample-data signaled

### Database Content Scan (`/scan-database`)
- Reads up to 1000 rows/documents per table/collection.
- For each column/field:
  - counts regex matches per PII type,
  - picks a primary PII type if match ratio is above 50%,
  - stores additional non-primary matches as anomalies with confidence score.

### File Scan (`/scan-file`)
- Structured files: scans values column-by-column.
- Document/PDF/SQL text: scans combined text content for regex hits.
- PDF parser flow:
  - extract text with `PyPDF2`,
  - fallback OCR (`pdf2image` + `PaddleOCR`) when extracted text is sparse.
  - Hybrid NLP scanning (Regex + Microsoft Presidio) to produce detailed Vault-ready JSON payloads.

## Data Model (Internal Scan DB)

### `scans`
- `id` (PK)
- `name`
- `connector_id`
- `realm_name`
- `created_at`

### `column_scans`
- `id` (PK)
- `scan_id` (FK -> scans.id)
- `db_name`
- `table_name`
- `column_name`
- `total_rows`
- `primary_pii_type`
- `primary_pii_match_count`

### `scan_anomalies`
- `id` (PK)
- `column_scan_id` (FK -> column_scans.id)
- `pii_type`
- `match_count`
- `confidence_score`

Migration file: `migrations/versions/a0446fa2e830_initial_migration.py`.

## Configuration

`config.py` selects DB backend by `FLASK_ENV`:
- `development` (default): SQLite `pii_scans.db`
- `production`: Postgres using env vars

### Environment Variables
- `FLASK_ENV` (`development` or `production`)
- `SECRET_KEY`
- `POSTGRES_DB` (production)
- `POSTGRES_USER` (production)
- `POSTGRES_PASSWORD` (production)
- `DATABASE_URL` (production DB host)
- `DB_PORT` (production DB port, default `5432`)
- `FLASK_APP` (typically `app.py`)

## Run Locally (Poetry)

### Prerequisites
- Python `3.12.x`
- Poetry `1.7+`
- OS libraries for PDF OCR:
  - Poppler (`pdf2image`)

### Install
```bash
poetry install
```

### Configure (PowerShell example)
```powershell
$env:FLASK_APP="app.py"
$env:FLASK_ENV="development"
```

### Run migrations
```bash
poetry run flask db upgrade
```

### Start service
```bash
poetry run flask run --host 0.0.0.0 --port 5000
```

Service URL: `http://localhost:5000`

## Run With Docker Compose
```bash
docker compose up --build
```

Run migrations inside container:
```bash
docker compose run --rm vault_migration_service poetry run flask db upgrade
```

Container startup runs Gunicorn:
```text
poetry run gunicorn --bind 0.0.0.0:5000 app:app
```

## API Reference

Base URL: `http://localhost:5000`

### 1. Check Connection
`POST /check-connection`

Request body:
```json
{
  "db_type": "postgres",
  "db_name": "mydb",
  "user": "postgres",
  "password": "secret",
  "host": "localhost",
  "port": 5432
}
```

Success: `200 {"message":"Connection successful"}`

### 2. Get Schema + PII Confidence
`POST /get-schema`

Request body:
```json
{
  "db_type": "postgres",
  "db_name": "mydb",
  "user": "postgres",
  "password": "secret",
  "host": "localhost",
  "port": 5432,
  "scan_type": "dual"
}
```

`scan_type` values:
- `metadata`
- `dual`

Returns per-table/per-field confidence and sensitivity metadata.

### 3. Ingest One Table To Vault
`POST /get-table-data`

Headers:
- `Authorization: Bearer <token>`

Request body:
```json
{
  "db_type": "postgres",
  "db_name": "mydb",
  "user": "postgres",
  "password": "secret",
  "host": "localhost",
  "port": 5432,
  "table_name": "customers",
  "selected_columns": ["id", "email", "phone"],
  "vault_name": "my-vault"
}
```

Behavior:
- Reads records from one SQL table or one Mongo collection.
- Serializes dates/UUIDs.
- Sends payload to:
  - `https://policyengine.getpatronus.com/api/vault/vaults/{vault_name}/records/multiple`

### 4. Ingest Joined Multi-Table Data To Vault
`POST /ingest-table-data`

Headers:
- `Authorization: Bearer <token>`

Request body:
```json
{
  "db_type": "postgres",
  "db_name": "mydb",
  "user": "postgres",
  "password": "secret",
  "host": "localhost",
  "port": 5432,
  "vault_name": "my-vault",
  "join_key": "id",
  "tables_info": [
    {"table_name": "customers", "columns": ["id", "email"]},
    {"table_name": "orders", "columns": ["id", "amount"]}
  ]
}
```

Behavior:
- SQL: builds outer joins (when join key exists) and flattens rows.
- MongoDB: merges collection documents by `join_key`.
- Batches output before sending to Vault API.

### 5. Get Supported PII Types
`GET /get-pii-types`

Returns full PII type metadata catalog from `constants.py`.

### 6. Scan Database And Persist Results
`POST /scan-database`

Request body:
```json
{
  "db_type": "postgres",
  "db_name": "mydb",
  "user": "postgres",
  "password": "secret",
  "host": "localhost",
  "port": 5432,
  "connector_id": "crm-prod",
  "scan_name": "CRM Weekly Scan",
  "realm_name": "acme",
  "pii_ids": ["email", "phone", "aadhaar"]
}
```

Notes:
- If `pii_ids` omitted, scans against all built-in PII patterns.
- Existing scans for the same `connector_id` are deleted before new insert.

Response:
- `scan_id` for retrieving detailed results later.

### 7. Get Scan Result By ID
`GET /get-scan-results/<scan_id>`

Returns:
- scan metadata,
- column-level primary PII,
- anomaly list per column,
- total counts per PII type.

### 8. List Scans
`GET /get-scans`

Optional query:
- `realm_name=<name>`

Returns latest scans with summary fields (`column_count`, timestamps, etc.).

### 9. Scan Uploaded File
`POST /scan-file` (`multipart/form-data`)

Form fields:
- `file` (required)
- `realm_name` (optional)
- `password` (optional, used for ZIP/PDF decryption)

Response includes:
- generated `scan_id`
- per-file status (`success`, `error`, `skipped`)
- parser metadata where available

## Known Caveats
- `app.py` defines `POST /get-table-data` twice (ingestion handler and benchmark handler), which is a route conflict and should be consolidated.
- `scan_file` uses `/tmp/...` temporary path, which can be problematic on Windows native runs.
- `connectors.py` (Google Drive/Email connectors) is present but not wired to Flask routes.
- Some parser imports are optional and may require additional packages not declared in `pyproject.toml` (for example `textract`, `odfpy`, `striprtf`, DB-specific drivers).
- `docker-compose.yml` currently includes plaintext credentials; move secrets to environment/secret management before production use.

## Troubleshooting
- Encrypted PDF fails:
  - Install `pycryptodome` and pass `password` in `/scan-file`.
- OCR not working:
  - Ensure Poppler is installed and available in PATH. PaddleOCR runs natively via Python packages.
- MDB parsing fails:
  - Ensure MS Access ODBC driver is installed on host/container.
- Migration issues:
  - Verify `FLASK_APP=app.py` and correct DB env vars before running `flask db upgrade`.
