# Data Discovery — Enterprise Hybrid PII Detection & Redaction Platform

An **Agentic HR Operating System** built on a multi-engine hybrid intelligence pipeline that detects, classifies, and redacts Personally Identifiable Information (PII) across structured and unstructured enterprise data sources.

---

## Architecture

```
┌────────────────────┐
│    FastAPI API     │
└─────────┬──────────┘
          │
          ▼
┌─────────────────────────┐
│  Global Pipeline Manager│  ← lifecycle, timing, observability
└─────────┬───────────────┘
          │
          ▼
┌──────────────────────────┐
│   Ingestion Dispatcher   │  ← routes by file type, detects OCR need, doc_type hint
└──────────┬───────────────┘
           │
    ┌──────┼──────────────┐
    ▼      ▼              ▼
File    OCR/Vision    Metadata
Parser  (Azure DI)    Engine
    └──────┬──────────────┘
           ▼
┌──────────────────────────┐
│  Content Reconstruction  │  ← merges OCR + text layer, reading order, table spatial
└──────────┬───────────────┘
           ▼
┌──────────────────────────┐
│    Text Normalization    │  ← Unicode NFKC, ligatures, span-preserving alignment
└──────────┬───────────────┘
           ▼
┌──────────────────────────┐
│   Detection Dispatcher   │  ← collaborative multi-engine routing (NOT fallback)
└──────────┬───────────────┘
           │
  ┌────────┼────────────┐
  ▼        ▼            ▼
Regex    GLiNER       Otter
Engine  Semantic NER  Struct.
  └────────┼────────────┘
           ▼
┌──────────────────────────┐
│  LLM Semantic Engine     │  ← Ollama / qwen2.5:7b-instruct
│  (Ollama / Qwen)         │
└──────────┬───────────────┘
           ▼
┌──────────────────────────┐
│  Entity Resolution Layer │  ← span merge, dedup, confidence fusion
└──────────┬───────────────┘
           ▼
┌──────────────────────────┐
│  PII Classification &    │  ← 40 types, 12 categories, 5-tier sensitivity
│  Sensitivity Scoring     │
└──────────┬───────────────┘
           ▼
┌──────────────────────────┐
│    Redaction Engine      │  ← PDF overlay, DOCX inline, XLSX cell, Image bbox
└──────────┬───────────────┘
           ▼
┌──────────────────────────┐
│    Validation Layer      │  ← span checks, overlap conflicts, FP detection, F1
└──────────┬───────────────┘
           ▼
┌──────────────────────────┐
│  JSON + Redacted Output  │  ← unified schema: metadata, entities, redactions, metrics
└──────────────────────────┘
```

---

## MASTER PII Coverage (40 Types, 12 Categories)

| Category | PII Types |
|---|---|
| Government ID | aadhaar, pan, passport, voter_id, driving_license, ssn |
| Financial | credit_card, bank_account, upi, ifsc, expiry, cvv |
| Authentication | user_id, password |
| Personal | name, dob, address, nationality, marital_status |
| Medical | diagnosis, allergies, treatment_history, prescription, immunization, blood_group, mrn |
| Insurance | insurance_policy, insurance_provider |
| Demographic | gender, age |
| Employment | occupation, employee_id, corporate_email, organization |
| Educational | educational_qualification |
| Contact | email, phone |
| Geo | city, pincode |
| Other | ip_address |

---

## Detection Engines

| Engine | Handles | Model |
|---|---|---|
| **Regex** | Structured IDs — Aadhaar, PAN, Credit Card, Phone, Email, Password | Compiled patterns + Luhn check |
| **GLiNER** | Semantic NER — Names, Orgs, Occupations, Qualifications, Medical | `urchade/gliner_mediumv2.1` |
| **Otter** | Structural — Form key:value fields, table headers, section-context | Custom spaCy heuristics |
| **LLM** | Semantic reasoning — Medical narrative, inferred PII, OCR-corrupted labels | `qwen2.5:7b-instruct` via Ollama |
| **Presidio** | Cross-validation NER — PERSON, LOCATION, PHONE, IP | `en_core_web_sm` spaCy |

All engines run **collaboratively** (not as a fallback chain). Results are merged in the Entity Resolution Layer.

---

## Supported File Formats

| Format | Parser | Redaction |
|---|---|---|
| PDF (digital) | PyPDF2 text layer | PyMuPDF overlay |
| PDF (scanned) | Azure Document Intelligence OCR | PyMuPDF overlay |
| DOCX / DOC | python-docx | Inline text replacement |
| XLSX / XLS | openpyxl | Cell value masking |
| CSV | pandas | Column-level masking |
| Images (JPG/PNG/BMP/TIFF/WEBP) | Azure DI OCR + bboxes | PIL black rectangle |
| ODT / RTF | odfpy / striprtf | Text replacement |
| SQL | Custom parser | Text replacement |
| MDB (Access) | mdbtools | Column-level masking |
| ZIP archives | Auto-extract + dispatch | Per-file |

---

## API Endpoints

### File Scanning
```
POST /scan-file
  Upload a file and run the full hybrid PII detection pipeline.
  Returns unified JSON with entities, confidence scores, validation results.

  Form fields:
    file          — file upload (required)
    realm_name    — optional namespace tag
    password      — for encrypted PDFs / ZIPs
```

### Database Scanning
```
POST /scan-database         — scan a connected database for PII
GET  /get-scan-results/{id} — retrieve PII results for a scan
GET  /get-scans             — list all scans (filterable by realm_name)
```

### Redaction
```
POST /redact                — redact PII from a previously scanned file
POST /redact-upload         — upload + detect + redact in one step

  Redaction types:
    contextual  → [PERSON_NAME] [ADDRESS]    (default, readable)
    full        → XXXXXXXXXXXX               (passwords, CVV)
    partial     → XXXX-XXXX-1234            (credit cards, phones)
    mask        → ████████████              (PDF visual black box)
```

### Connections & Schema
```
POST /check-connection      — test a database connection
POST /get-schema            — inspect database schema
GET  /get-pii-types         — list all supported MASTER_PIIS
```

### Dashboard
```
GET  /dashboard/summary     — aggregate PII scan statistics
GET  /scan-connector/{id}   — scan results for a specific connector
```

---

## Unified JSON Output Schema

Every `/scan-file` response:

```json
{
  "status": "success",
  "document_metadata": {
    "scan_id": 42,
    "filename": "patient_report.pdf",
    "doc_type": "medical",
    "parser_type": "pdf",
    "needs_ocr": true,
    "page_count": 3,
    "block_count": 47,
    "char_count": 12450,
    "routing_rationale": ["extension=.pdf → parser=pdf", "content heuristic: medical=8"]
  },
  "entities": [
    {
      "pii_type": "aadhaar",
      "value": "123456789012",
      "confidence": 1.0,
      "sources": ["regex"],
      "sensitivity": "Very High",
      "span": {"start": 120, "end": 132},
      "context": "Patient UID: 1234 5678 9012 as per records"
    }
  ],
  "pii_entities": {
    "aadhaar": [{"value": "123456789012", "confidence": 1.0, "sources": ["regex"]}],
    "name":    [{"value": "Rahul Sharma",  "confidence": 0.87, "sources": ["gliner"]}]
  },
  "redactions": [
    {"pii_type": "aadhaar", "original": "123456789012", "replacement": "[AADHAAR_NUMBER]"}
  ],
  "confidence_scores": {"aadhaar": 1.0, "name": 0.87, "email": 1.0},
  "processing_metrics": {
    "total_ms": 843.2,
    "engines_used": ["regex", "otter", "gliner", "presidio"],
    "entity_count": 14,
    "ocr_used": true
  },
  "validation_results": {
    "passed": true,
    "issues": 0,
    "overlap_conflicts": 0,
    "false_positives": 0,
    "missed_entities": 0,
    "redaction_coverage": 1.0
  }
}
```

---

## Project Structure

```
.
├── main.py                          # FastAPI entry point — registers routers, DB init on startup
├── auth.py                          # JWT Bearer auth — validates org_name claim
├── config.py                        # DB config — SQLite (dev) / PostgreSQL (prod)
├── database.py                      # SQLAlchemy engine, SessionLocal, get_db() dependency
├── models.py                        # ORM models: Scan, ColumnScan, ScanAnomaly, PIILocation
├── schemas.py                       # Pydantic request validation schemas for all endpoints
├── constants.py                     # MASTER_PIIS — 40 PII type definitions, sensitivity levels
├── db_utils.py                      # Database connection builders (PostgreSQL, MySQL, MongoDB, etc.)
├── connectors.py                    # Google Drive + Email connectors (not yet wired to routes)
│
├── routers/
│   ├── files.py                     # POST /scan-file — full 15-layer hybrid pipeline endpoint
│   ├── redact.py                    # POST /redact, /redact-upload — PDF/DOCX/XLSX/Image redaction
│   ├── scans.py                     # GET /get-scans, /get-scan-results — scan retrieval
│   ├── connections.py               # POST /check-connection, /get-schema, /get-pii-types
│   ├── data.py                      # POST /get-table-data, /ingest-table-data, /benchmark
│   ├── dashboard.py                 # GET /dashboard/summary — aggregated PII statistics
│   └── scan_connector.py            # Connector-level scan management endpoints
│
├── services/
│   ├── pipeline_manager.py          # Global Pipeline Manager — per-request context, timing, logs
│   ├── ingestion_dispatcher.py      # Ingestion Dispatcher — file routing, OCR detection, doc_type
│   ├── content_reconstruction.py    # Content Reconstruction — merges OCR + text, reading order
│   ├── text_normalizer.py           # Text Normalization — Unicode NFKC, span-preserving alignment
│   ├── detection_dispatcher.py      # Detection Dispatcher — orchestrates all engines in parallel
│   ├── entity_resolution.py         # Entity Resolution — span merge, dedup, confidence fusion
│   ├── pii_service.py               # Public API — detect_pii(), select_primary_pii() (stable interface)
│   ├── redaction_engine.py          # Redaction Engine — PDF overlay, DOCX, XLSX, Image, CSV
│   ├── validator.py                 # Validation Layer — FP checks, span correctness, F1 scoring
│   ├── output_schema.py             # Unified Output — builds final JSON response structure
│   ├── ocr_worker.py                # OCR Subprocess — Azure Document Intelligence (child process)
│   │
│   └── engines/
│       ├── base_engine.py           # Abstract base — BaseEngine interface, PIIMatch, EngineResult
│       ├── regex_engine.py          # Regex Engine — 40-type deterministic patterns, Luhn validation
│       ├── gliner_engine.py         # GLiNER Engine — zero-shot semantic NER, 40+ label mapping
│       ├── otter_engine.py          # Otter Engine — form fields, table headers, section context
│       └── llm_engine.py            # LLM Engine — Ollama/Qwen JSON extraction, fuzzy type resolver
│
├── parsers/
│   ├── base.py                      # BaseParser abstract class — parse() + validate() interface
│   ├── structured/
│   │   ├── csv_parser.py            # CSV — pandas column extraction + metadata
│   │   └── excel_parser.py          # Excel — openpyxl multi-sheet traversal
│   └── unstructured/
│       ├── document_parser.py       # DOCX/DOC/ODT/RTF, PDFParser, ImageParser + OCR subprocess
│       ├── access_parser.py         # MDB/Access database table extraction
│       └── sql_parser.py            # SQL file — DDL table definitions + DML value extraction
│
├── tests/
│   ├── test_pii_service.py          # Unit tests for the full PII detection pipeline
│   ├── test_pdf_parser.py           # PDF text extraction + OCR fallback tests
│   ├── test_sample_images.py        # Image OCR + bounding box extraction tests
│   └── test_llm_pii_baseline.py     # LLM engine baseline accuracy + precision/recall tests
│
├── migrations/                      # Alembic DB migrations (use: alembic upgrade head)
├── requirements.txt                 # All Python dependencies
├── Dockerfile                       # Container image build
└── docker-compose.yml               # Local dev stack (app + postgres)
```

---

## Setup

### Prerequisites
- Python 3.9+
- [Ollama](https://ollama.ai) with `qwen2.5:7b-instruct` — `ollama pull qwen2.5:7b-instruct`
- Azure Document Intelligence endpoint + API key (for OCR on scanned PDFs / images)

### Install

```bash
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python -m spacy download en_core_web_sm
```

### Environment Variables

```bash
# OCR (required for scanned PDFs + images)
DOCUMENTINTELLIGENCE_ENDPOINT=https://your-resource.cognitiveservices.azure.com/
DOCUMENTINTELLIGENCE_API_KEY=your-key

# Production DB (optional — defaults to SQLite in dev)
FLASK_ENV=production
POSTGRES_DB=pii_db
POSTGRES_USER=admin
POSTGRES_PASSWORD=secret
DATABASE_URL=localhost
DB_PORT=5432
```

### Run

```bash
# Development
uvicorn main:app --host 0.0.0.0 --port 8000 --reload

# Docker
docker compose up --build
```

### Authentication

All endpoints require a JWT Bearer token:

```python
import jwt
token = jwt.encode({"org_name": "Patronus1"}, "super_secret_key", algorithm="HS256")
# curl -H "Authorization: Bearer <token>" http://localhost:8000/...
```

---

## Key Design Principles

**Collaborative engines, not fallback** — all engines run on every document. Regex handles structured IDs with 100% precision; GLiNER and Otter catch semantic/contextual entities; Qwen reasons about medical narrative text.

**Original text always preserved** — the Text Normalization layer operates on a copy, building an alignment table for bidirectional span mapping so redaction hits exact character positions.

**OCR in a subprocess** — `ocr_worker.py` runs Azure Document Intelligence in a child process. A crash kills only the child; the scan continues with empty OCR output rather than taking down the service.

**Backward-compatible public API** — `services/pii_service.py` preserves `detect_pii()` / `select_primary_pii()`. All routers work unchanged while internally delegating to the new multi-engine dispatcher.

---

## Tech Stack

| Layer | Technology |
|---|---|
| API Framework | FastAPI + Uvicorn |
| Database | SQLite (dev) / PostgreSQL (prod) via SQLAlchemy |
| Semantic NER | GLiNER `urchade/gliner_mediumv2.1` |
| Cross-validation NER | Presidio Analyzer + spaCy `en_core_web_sm` |
| LLM Reasoning | Ollama → `qwen2.5:7b-instruct` |
| PDF Text | PyPDF2 |
| PDF Redaction | PyMuPDF (fitz) |
| OCR | Azure Document Intelligence |
| Document Parsing | python-docx, openpyxl, odfpy, striprtf |
| Image Redaction | Pillow |
| Auth | PyJWT HS256 |
| Containerization | Docker + docker-compose |
