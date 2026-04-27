# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

```bash
# Install dependencies
pip install -r requirements.txt
# Also install the spaCy model (bundled in requirements.txt via direct URL):
python -m spacy download en_core_web_sm

# Start development server (FastAPI on port 8000)
uvicorn main:app --host 0.0.0.0 --port 8000 --reload

# Run tests
pytest tests/

# Run a single test file
pytest tests/test_pii_service.py -v

# Docker
docker compose up --build
```

DB tables are created automatically on startup via SQLAlchemy `create_all` in the FastAPI lifespan event — no migration command needed in development. For production schema changes use Alembic (`alembic upgrade head`).

The legacy `app.py` (Flask, port 5000) still exists but `main.py` (FastAPI, port 8000) is the active entry point.

## Architecture

The service is a PII detection and data migration tool. It connects to source databases or accepts file uploads, scans them for PII, stores results locally, and can ingest records into the Patronus Vault API (`https://policyengine.getpatronus.com/api/vault/...`).

### Key files

- **`main.py`** — FastAPI entry point; registers routers, adds CORS middleware, triggers `create_all` on startup
- **`database.py`** — SQLAlchemy engine + `SessionLocal` factory + `get_db()` FastAPI dependency
- **`schemas.py`** — Pydantic request models for all endpoints (used by FastAPI for validation and Swagger docs)
- **`models.py`** — three ORM models: `Scan`, `ColumnScan`, `ScanAnomaly`
- **`config.py`** — SQLite in development, PostgreSQL in production (switched by `FLASK_ENV`)
- **`constants.py`** — PII type definitions with regex patterns, sensitivity levels, and categories
- **`services/pii_service.py`** — hybrid PII detection engine (see below)
- **`db_utils.py`** — SQLAlchemy/PyMongo connection builders and schema-level scanning logic
- **`connectors.py`** — Google Drive and Email connectors (not wired to any routes)
- **`app.py`** — legacy monolithic Flask app (kept for reference, superseded by `main.py`)

### Routers

All route handlers live in `routers/`:

| File | Endpoints |
|------|-----------|
| `connections.py` | `/check-connection`, `/get-schema`, `/get-pii-types` |
| `data.py` | `/get-table-data`, `/ingest-table-data`, `/benchmark-table-data` |
| `scans.py` | `/scan-database`, `/get-scan-results/{scan_id}`, `/get-scans` |
| `files.py` | `/scan-file` |

`routers/scans.py` also exports `process_column_data` and `process_document_content` — shared helpers used by `routers/files.py`.

### PII detection — three-layer hybrid pipeline (`services/pii_service.py`)

The new engine replaces the single-regex approach:

1. **Layer 1 — Regex** (`_detect_with_regex`): deterministic patterns from `constants.py` compiled once at import. Credit cards run a Luhn check. For `address`, `name`, and `organization`, regex is skipped when NLP is enabled (`_PRESIDIO_PREFERRED_TYPES`) because Presidio handles those better.

2. **Layer 2 — Presidio NER** (`_detect_with_presidio`): runs `en_core_web_sm` spaCy model via `AnalyzerEngine` (loaded once via `@lru_cache`). Includes custom recognizers for Indian PII: `IN_PAN`, `IN_AADHAAR`, `IN_VOTER`. `EmailRecognizer` is removed from Presidio's registry (it uses tldextract → network call; our regex covers it). `tldextract` is patched offline before the engine loads.

3. **Layer 3 — Merge** (`_merge`): keeps all regex hits; drops Presidio hits that overlap the same span and type. Deduplicates by value for types like email, phone, PAN. `select_primary_pii` picks the winner by sensitivity priority (`_PII_PRIORITY`) then weighted confidence score — replaces the old 50%-threshold rule.

Entry point: `detect_pii(text, use_nlp=True) → PIIResult`. Use `use_nlp=False` for DB column values (short, structured, high throughput).

### Supported PII types

Regex: `email`, `phone`, `dob`, `pan`, `aadhaar`, `credit_card`, `expiry`, `cvv`  
Presidio (NER): `name`, `address`, `ip_address`, `voter_id`

### Database schema

Three tables, schema owned by SQLAlchemy `Base.metadata.create_all`:

- `scans` — top-level record (`name`, `connector_id`, `realm_name`, `created_at`)
- `column_scans` — per-column findings (`scan_id` FK, `db_name`, `table_name`, `column_name`, `primary_pii_type`, `primary_pii_match_count`, `total_rows`)
- `scan_anomalies` — secondary PII hits (`column_scan_id` FK, `pii_type`, `match_count`, `confidence_score`)

### File parsing

`routers/files.py` now supports images in addition to previous formats. Parser selection via `_get_parser()`:

**Structured (column-level scanning):** `.csv`, `.xlsx/.xls`, `.mdb`  
**Unstructured (full-text scanning):** `.pdf`, `.docx/.doc`, `.odt`, `.rtf`, `.sql`  
**Images (new):** `.jpg/.jpeg`, `.png`, `.bmp`, `.tif/.tiff`, `.webp` — handled by `ImageParser`  
**Archives:** `.zip` (password-protected supported); extracted and each file dispatched individually

OCR backend: **Tesseract** (`apt install tesseract-ocr` + `pytesseract` Python wrapper). Low memory footprint (~50 MB resident), ARM64-compatible via apt. Runs in a child process via `services/ocr_worker.py` — a crash in the worker kills only the child, not uvicorn. PDF still tries PyPDF2 text extraction first; falls back to OCR only if extracted text < 100 characters.

Temp files now use `tempfile.NamedTemporaryFile` (cross-platform) instead of `/tmp/` hardcoding.

### Supported data sources

**Databases:** `postgres`, `mysql`, `sqlite`, `mssql`, `oracle`, `mariadb`, `mongodb_standard`, `mongodb_srv`

> Note: `/get-schema` schema inspection only has specific branches for Postgres, Oracle, and MongoDB — other SQL dialects fall through to a generic path.

## Environment variables

| Variable | Purpose |
|----------|---------|
| `FLASK_ENV` | `development` (SQLite) or `production` (PostgreSQL) |
| `POSTGRES_DB` | Database name (production) |
| `POSTGRES_USER` | DB user (production) |
| `POSTGRES_PASSWORD` | DB password (production) |
| `DATABASE_URL` | DB host (production) |
| `DB_PORT` | DB port, defaults to 5432 |
| `DOCUMENTINTELLIGENCE_ENDPOINT` | Azure Document Intelligence endpoint URL |
| `DOCUMENTINTELLIGENCE_API_KEY` | Azure Document Intelligence API key |

## Known issues

- `app.py` still defines `/get-table-data` twice — irrelevant to `main.py` but confusing if Flask is run directly
- Some parser dependencies (`odfpy`, `striprtf`, Oracle/MSSQL drivers) are not in `requirements.txt` but expected at runtime
- `docker-compose.yml` contains plaintext credentials
