# PII Engine Pipeline Observability

Enterprise-grade observability layer for the PII detection pipeline, enabling real-time debugging, performance tracking, and comprehensive verification.

## Overview

This observability system provides:

- **Structured Logging**: Every pipeline stage logs input, output, strategy decisions, and timing
- **Pipeline Context Tracking**: Request-scoped context with timing, errors, and metadata
- **Stage Logging Decorators**: Automatic timing and error tracking for functions
- **Debug Dumps**: Intermediate outputs saved for debugging (raw text, chunks, matches, entities)
- **Output Validation**: JSON schema validation with entity verification
- **Performance Metrics**: Timing, throughput, and quality metrics

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                        FastAPI Endpoint                                  │
│  POST /scan-file → logs_filename, content_type, request_id             │
└─────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                       Pipeline Runner                                   │
│  [UPLOAD] → [PARSER] → [OCR?] → [LANG] → [REGEX] → [NER] → [RESOLVE]   │
│     │         │          │        │        │         │        │       │
│     └─────────┴──────────┴────────┴────────┴─────────┴────────┴─────── │
│                              Debug Dumper                                │
│   debug/                                                                  │
│   ├── raw_text/                                                          │
│   ├── ocr_text/                                                          │
│   ├── regex_matches/                                                     │
│   ├── ner_entities/                                                      │
│   └── final_json/                                                        │
└─────────────────────────────────────────────────────────────────────────┘
```

## Terminal Output

With this observability layer, you'll see logs like:

```
2025-01-05 10:30:45 | INFO | pii_engine.pipeline | ================================================================================
2025-01-05 10:30:45 | INFO | pii_engine.pipeline | [UPLOAD] file=employee_passport.pdf size_bytes=102400 content_type=application/pdf
2025-01-05 10:30:45 | INFO | pii_engine.pipeline | [PARSER] Selected: PDFParser
2025-01-05 10:30:46 | INFO | pii_engine.pipeline | [TEXT] chars=5412 words=847
2025-01-05 10:30:46 | INFO | pii_engine.pipeline | [LANG] Detected: en
2025-01-05 10:30:46 | INFO | pii_engine.parser | [parser] START | parse | file=employee_passport.pdf
2025-01-05 10:30:47 | INFO | pii_engine.parser | [parser] SUCCESS | parse | 1234.56ms | chars=5412
2025-01-05 10:30:47 | INFO | pii_engine.detector | [regex] START | detect_pii
2025-01-05 10:30:47 | INFO | pii_engine.detector | [REGEX] matches=14
2025-01-05 10:30:47 | INFO | pii_engine.detector | [NER] entities=19
2025-01-05 10:30:47 | INFO | pii_engine.resolver | [RESOLUTION] merged=22 (from 14 regex + 8 ner)
2025-01-05 10:30:47 | INFO | pii_engine.validation | [VALIDATION] schema=PASS
2025-01-05 10:30:47 | INFO | pii_engine.pipeline | [OUTPUT] saved=results/output_abc123_20250105_103047.json
2025-01-05 10:30:47 | INFO | pii_engine.pipeline | ================================================================================
2025-01-05 10:30:47 | INFO | pii_engine.pipeline | [PIPELINE COMPLETE] request_id=a1b2c3d4 entities=22 elapsed=3.42s
2025-01-05 10:30:47 | INFO | pii_engine.pipeline | ================================================================================
```

## Components

### 1. Structured Logging Layer

**File**: `services/pii_engine/utils/logger.py`

Enterprise-grade logging with:
- Timestamp, level, logger name, and message
- JSON format option for log aggregation (ELK, Splunk)
- Stage markers for filtering

```python
from services.pii_engine.utils.logger import setup_logger, get_logger

logger = setup_logger("pii_engine.parser")
logger.info("[PARSER] Selected PDF parser")
logger.warning("[OCR] Text extraction empty -> OCR fallback")
```

### 2. Pipeline Context Tracker

**File**: `services/pii_engine/core/pipeline_context.py`

Tracks:
- `request_id`: Unique identifier for each pipeline run
- `timing`: Start time, elapsed time, stage durations
- `metadata`: File info, parser selection, entity counts
- `errors`: Any errors encountered

```python
from services.pii_engine.core import PipelineContext

ctx = PipelineContext()
ctx.set_file_metadata("document.pdf", "application/pdf", 102400)

with ctx.track_stage("parser") as stage:
    result = parser.parse(file_path)
    stage.set_output(len(result.text), parser_name="PDFParser")

print(ctx.elapsed())  # 3.42
print(ctx.get_stage_report())  # Full JSON report
```

### 3. Stage Logging Decorator

**File**: `services/pii_engine/utils/stage_logger.py`

Automatic logging for functions:

```python
from services.pii_engine.utils.logger import get_logger
from services.pii_engine.utils.stage_logger import log_stage

logger = get_logger("pii_engine.parser")

@log_stage(logger, "PARSER")
def parse_file(file_path: str) -> dict:
    return {"text": "..."}

# Logs:
# [PARSER] START | parse_file | file=document.pdf
# [PARSER] SUCCESS | parse_file | 1234.56ms | chars=5412
```

### 4. Debug Dumper

**File**: `services/pii_engine/utils/debug_dumper.py`

Saves intermediate outputs for debugging:

```
debug/
├── raw_text/
│   └── 2025-01-05_103045_document_raw.txt
├── ocr_text/
│   └── 2025-01-05_103045_document_ocr.txt
├── chunks/
│   └── 2025-01-05_103045_document_chunk_0.txt
├── regex_matches/
│   └── 2025-01-05_103045_document_regex.json
├── ner_entities/
│   └── 2025-01-05_103045_document_ner.json
└── final_json/
    └── 2025-01-05_103045_document_output.json
```

```python
from services.pii_engine.utils import DebugDumper

dumper = DebugDumper(debug_dir="debug", enabled=True)
dumper.dump_raw_text(text, "document.pdf")
dumper.dump_regex_matches(matches, "document.pdf")
dumper.dump_output_json(output, "document.pdf")
```

### 5. Output Validator

**File**: `services/pii_engine/validation/output_validator.py`

Validates:
- All required fields present
- Span offsets are valid
- Confidence scores in range [0, 1]
- Entity types are recognized
- Deduplication performed
- Source parser tracked

```python
from services.pii_engine.validation import validate_output, format_validation_errors

output = {
    "entities": [
        {"type": "EMAIL", "value": "test@example.com", "confidence": 0.95}
    ],
    "metadata": {"parser": "PDFParser"}
}

result = validate_output(output)
if not result.valid:
    print(format_validation_errors(result))
```

### 6. Pipeline Runner

**File**: `services/pii_engine/pipeline_runner.py`

Orchestrates the full pipeline:

```python
from services.pii_engine.pipeline_runner import run_pipeline, get_pipeline_metrics

result = run_pipeline(
    file_path="document.pdf",
    use_nlp=True,
    debug=True,
    output_dir="results"
)

print(f"Success: {result.success}")
print(f"Entities: {len(result.entities)}")
print(f"Elapsed: {result.timing['total_seconds']:.2f}s")

metrics = get_pipeline_metrics(result)
print(f"Throughput: {metrics['throughput']['entities_per_second']:.2f} entities/s")
```

## File Type Support Matrix

| Format | Extension | Parser | Tested |
|--------|-----------|--------|--------|
| PDF | `.pdf` | PDFParser | ✓ |
| Word | `.docx`, `.doc` | DocumentParser | ✓ |
| OpenDocument | `.odt` | DocumentParser | ✓ |
| RTF | `.rtf` | DocumentParser | ✓ |
| Plain Text | `.txt` | (native) | ✓ |
| PNG | `.png` | ImageParser (OCR) | ✓ |
| JPEG | `.jpg`, `.jpeg` | ImageParser (OCR) | ✓ |
| CSV | `.csv` | CSVParser | ✓ |
| Excel | `.xlsx`, `.xls` | ExcelParser | ✓ |
| Access | `.mdb` | MDBParser | ✓ |
| SQL | `.sql` | SQLParser | ✓ |
| Email | `.eml` | EmailParser | ✓ |
| HTML | `.html` | HTMLParser | ✓ |

## Testing Ground Truth

Create test documents with known PIIs:

```python
# tests/fixtures/test_document.txt
John Doe
john.doe@gmail.com
+971501234567
Passport: N1234567
Aadhaar: 1234-5678-9012

# Expected JSON:
{
    "EMAIL": 1,
    "PHONE": 1,
    "PASSPORT": 1,
    "AADHAAR": 1
}
```

Test:

```python
def test_ground_truth():
    result = run_pipeline("tests/fixtures/test_document.txt")
    entity_types = {e["type"] for e in result.entities}
    
    assert "EMAIL" in entity_types
    assert "PHONE" in entity_types
    assert "AADHAAR" in entity_types
```

## Failure Injection Tests

Test graceful degradation:

```python
# Corrupted PDF
def test_corrupted_pdf():
    result = run_pipeline("corrupted.pdf")
    # Should not crash - may fail but gracefully
    if not result.success:
        assert "error" in result.errors[0].lower()

# Empty file
def test_empty_file():
    result = run_pipeline("empty.txt")
    # Should succeed with 0 entities
    assert result.success or "empty" in " ".join(result.errors).lower()

# Large file (stress test)
def test_large_file():
    large_text = "test@email.com\n" * 10000
    # ... create file and run pipeline
    assert result.success
    assert len(result.entities) >= 10000
```

## Verification Checklist

### Parser Layer
- [ ] Correct parser selected for each file type
- [ ] Extraction not empty for valid files
- [ ] OCR fallback works for scanned documents
- [ ] Multilingual extraction works

### Pipeline Layer
- [ ] All stages execute (parser → regex → ner → resolution)
- [ ] No silent exceptions
- [ ] Timings logged for each stage
- [ ] `request_id` propagated throughout

### Detection Layer
- [ ] Regex entities extracted correctly
- [ ] NER entities extracted correctly
- [ ] Hybrid resolution merges without duplicates
- [ ] Confidence scores present

### Output Layer
- [ ] JSON schema valid
- [ ] Offsets correct (if present)
- [ ] Confidence scores in [0, 1]
- [ ] Metadata included

## Performance Metrics

Track:
- `parse_time`: Time in parser
- `ocr_time`: Time in OCR (if used)
- `ner_time`: Time in NER
- `regex_time`: Time in regex
- `total_time`: End-to-end
- `memory_usage`: Peak memory

## Most Important Architectural Rule

**DO NOT only log errors.**

Log:
- Strategy decisions ("Selected PDFParser")
- Fallback activations ("OCR fallback triggered")
- Counts ("matches=14", "entities=19")
- Timings ("1234.56ms")
- Entity totals ("merged=22")
- Parser selections

Without that, debugging enterprise ingestion becomes impossible.

## Example: Full Pipeline Run

```python
from services.pii_engine.pipeline_runner import run_pipeline

# Run with full observability
result = run_pipeline("employee_passport.pdf", debug=True)

if result.success:
    print(f"Found {len(result.entities)} entities:")
    for entity in result.entities:
        print(f"  {entity['type']}: {entity['value']} ({entity['confidence']:.2f})")
    
    print(f"\nTiming:")
    for stage, ms in result.timing['stages'].items():
        print(f"  {stage}: {ms:.2f}ms")
    print(f"  Total: {result.timing['total_seconds']:.2f}s")
else:
    print(f"Failed: {result.errors}")
```

Output:
```
================================================================================
[PIPELINE START] request_id=a1b2c3d4 file=employee_passport.pdf
[PARSER] Selected: PDFParser
[TEXT] chars=5412 words=847
[LANG] Detected: en
[REGEX] matches=14
[NER] entities=8
[RESOLUTION] merged=22
[VALIDATION] schema=PASS
[OUTPUT] saved=results/output_a1b2c3d4.json
================================================================================
[PIPELINE COMPLETE] request_id=a1b2c3d4 entities=22 elapsed=3.42s
================================================================================

Found 22 entities:
  EMAIL: john.doe@gmail.com (0.99)
  PHONE: +971501234567 (0.95)
  ...

Timing:
  parser: 1234.56ms
  regex: 45.23ms
  ner: 890.12ms
  resolution: 12.34ms
  validation: 5.67ms
  output: 123.45ms
  Total: 3.42s
```

## Directory Structure

```
services/pii_engine/
├── __init__.py
├── pipeline_runner.py       # Main orchestration with logging
├── core/
│   ├── __init__.py
│   └── pipeline_context.py  # Context tracking
├── utils/
│   ├── __init__.py
│   ├── logger.py            # Structured logging
│   ├── stage_logger.py      # Stage decorators
│   └── debug_dumper.py      # Intermediate dumps
└── validation/
    ├── __init__.py
    └── output_validator.py  # JSON schema validation

tests/
├── test_file_parsing_matrix.py   # File type tests
├── fixtures/
│   └── ground_truth/              # Known PII documents
└── ...

debug/                              # Debug output directory
├── raw_text/
├── ocr_text/
├── chunks/
├── regex_matches/
├── ner_entities/
└── final_json/
```

## Dependencies

```
# Already installed
python-dotenv>=1.0.0
fastapi>=0.100.0
sqlalchemy>=2.0.0
presidio-analyzer>=2.2.0
paddleocr>=2.7.0
azure-ai-documentintelligence>=1.0.0b1

# Optional (for rich terminal output)
rich>=13.0.0
```

## Future Enhancements

1. **Rich Terminal Progress**: Add `rich` library for progress bars and colored output
2. **Prometheus Metrics**: Export metrics for Prometheus/Grafana monitoring
3. **Distributed Tracing**: OpenTelemetry integration for distributed tracing
4. **Memory Profiling**: Track memory usage during pipeline execution
5. **Batch Processing**: Parallel processing with progress tracking