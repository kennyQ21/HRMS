"""
services/output_schema.py
---------------------------
Simplified document-centric output schema.

Architecture:
  - NO per-ID-card structured_fields (brittle, maintenance-heavy)
  - entity_groups: type -> [values] — stable, schema-light
  - document_hints: lightweight classification signals
  - Address consolidation preserved (high value)
  - Entity quality filter preserved
  - Compliance-focused, deterministic, thin output layer

Output structure:
{
  "status":            "success",
  "document_metadata": {},
  "entities":          [],
  "entity_groups":     {},
  "document_hints":    {},
  "ocr":               {},
  "validation_results":{},
  "redactions":        {},
  "processing_metrics":{}
}
"""

from __future__ import annotations

import re
from typing import Any, Optional


# ── Entity quality filter ─────────────────────────────────────────────────────

_NATIONALITY_JUNK: frozenset[str] = frozenset({
    "of india", "india", "of", "the", "government", "government of india",
})
_ADDRESS_NOISE_RE = re.compile(
    r"^(?:[A-Z]{1,3}|[^A-Za-z0-9,]+|\?+|[0-9]{1,3})$"
)
_MIN_VALUE_LEN: dict[str, int] = {
    "address": 6,
    "nationality": 4,
    "organization": 3,
}


def _is_clean_entity(ptype: str, value: str) -> bool:
    """Return False for low-quality / OCR-garbage entity values."""
    v = value.strip()
    if not v:
        return False
    if ptype == "nationality" and v.lower() in _NATIONALITY_JUNK:
        return False
    if len(v) < _MIN_VALUE_LEN.get(ptype, 2):
        return False
    if ptype == "address" and _ADDRESS_NOISE_RE.match(v):
        return False
    return True


# ── Address consolidation ─────────────────────────────────────────────────────

_PINCODE_RE  = re.compile(r"\b(\d{6})\b")
_STATE_CODES = {
    "gujarat": "Gujarat", "maharashtra": "Maharashtra",
    "karnataka": "Karnataka", "tamil nadu": "Tamil Nadu",
    "telangana": "Telangana", "kerala": "Kerala",
    "rajasthan": "Rajasthan", "uttar pradesh": "Uttar Pradesh",
    "madhya pradesh": "Madhya Pradesh", "west bengal": "West Bengal",
    "punjab": "Punjab", "haryana": "Haryana", "bihar": "Bihar",
    "odisha": "Odisha", "assam": "Assam", "jharkhand": "Jharkhand",
    "uttarakhand": "Uttarakhand", "himachal pradesh": "Himachal Pradesh",
    "goa": "Goa", "delhi": "Delhi", "andhra pradesh": "Andhra Pradesh",
    "north carolina": "North Carolina", "california": "California",
    "new york": "New York", "texas": "Texas", "florida": "Florida",
}
_CITY_NAMES = {
    "rajkot", "morvi", "mumbai", "delhi", "bangalore", "bengaluru",
    "chennai", "hyderabad", "kolkata", "pune", "ahmedabad", "surat",
    "jaipur", "lucknow", "kanpur", "nagpur", "indore", "thane",
    "bhopal", "visakhapatnam", "patna",
}


def _consolidate_address(address_entities: list) -> dict[str, Any]:
    """Merge multiple address fragment entities into one structured address."""
    clean = [
        e for e in address_entities
        if _is_clean_entity("address", e.value) and len(e.value) > 5
    ]
    if not clean:
        return {}

    clean.sort(key=lambda e: e.start if e.start >= 0 else 9999)

    parts = []
    seen: set[str] = set()
    for e in clean:
        v = e.value.strip().rstrip(",").strip()
        key = re.sub(r"\s+", " ", v).lower()
        if key not in seen:
            seen.add(key)
            parts.append(v)

    full = ", ".join(parts)
    result: dict[str, Any] = {"full": full}
    full_lower = full.lower()

    pin = _PINCODE_RE.search(full)
    if pin:
        result["postal_code"] = pin.group(1)

    for state_lower, state_proper in _STATE_CODES.items():
        if state_lower in full_lower:
            result["state"] = state_proper
            break

    for city in _CITY_NAMES:
        if city in full_lower:
            result["city"] = city.title()
            break

    return result


# ── Entity grouping (replaces structured_fields) ─────────────────────────────

def build_entity_groups(resolved_entities: list) -> dict[str, Any]:
    """
    Build clean, consumer-facing entity groups from resolved entities.

    Groups entities by pii_type, consolidates addresses, picks best values.
    Replaces the old per-ID-card structured_fields which was brittle and
    required constant maintenance for every new document type.
    """
    by_type: dict[str, list] = {}
    for e in resolved_entities:
        if not _is_clean_entity(e.pii_type, e.value):
            continue
        by_type.setdefault(e.pii_type, []).append(e)

    groups: dict[str, Any] = {}

    for ptype, items in by_type.items():
        if ptype == "address":
            addr = _consolidate_address(items)
            if addr:
                groups["address"] = addr
            continue

        best = max(items, key=lambda e: e.confidence)
        key = {
            "aadhaar": "aadhaar_number",
            "pan":     "pan_number",
            "dob":     "date_of_birth",
            "mrn":     "medical_record_number",
        }.get(ptype, ptype)

        groups[key] = {
            "value":      best.value,
            "confidence": round(best.confidence, 3),
        }

    return groups


# ── Document hints (lightweight classification) ──────────────────────────────

def _build_document_hints(resolved_entities: list, content_doc=None) -> dict[str, bool]:
    """
    Derive lightweight document classification hints from detected entities.
    Replaces the old doc_type-specific structured_fields.
    """
    types_present = {e.pii_type for e in resolved_entities}

    govt_id_types = {"aadhaar", "pan", "passport", "voter_id", "driving_license",
                     "abha_number", "ssn"}
    medical_types = {"diagnosis", "prescription", "mrn", "allergies", "treatment_history",
                     "blood_group", "immunization", "lab_test_results", "medication"}
    financial_types = {"bank_account", "ifsc", "credit_card", "upi", "annual_income",
                       "credit_score"}

    ocr_used = False
    if content_doc:
        ocr_used = any(b.source == "ocr" for b in content_doc.blocks)

    return {
        "contains_government_id":  bool(types_present & govt_id_types),
        "contains_medical_data":   bool(types_present & medical_types),
        "contains_financial_data": bool(types_present & financial_types),
        "ocr_used":                ocr_used,
    }


# ── OCR quality ───────────────────────────────────────────────────────────────

def _ocr_quality(content_doc, char_count: int) -> dict[str, Any]:
    if content_doc is None:
        return {"used": False}
    ocr_used = any(b.source == "ocr" for b in content_doc.blocks)
    review_required = ocr_used and char_count < 100
    return {
        "used": ocr_used,
        "quality": {
            "char_count": char_count,
            "manual_review_required": review_required,
        },
    }


# ── Main builder ──────────────────────────────────────────────────────────────

def build_scan_response(
    scan_id: int,
    filename: str,
    resolved_entities: list,
    engine_results: list,
    content_doc,
    ingestion_plan,
    validation_report=None,
    redaction_map: Optional[dict] = None,
    redaction_verification: Optional[dict] = None,
    elapsed_ms: float = 0.0,
    language: Optional[str] = None,
    debug: bool = False,
    ocr_ms: float = 0.0,
    detection_ms: float = 0.0,
    resolution_ms: float = 0.0,
) -> dict[str, Any]:
    """Assemble the canonical document-centric JSON response."""
    doc_type    = ingestion_plan.doc_type if ingestion_plan else "generic"
    parser_type = ingestion_plan.parser_type if ingestion_plan else "unknown"
    char_count  = len(content_doc.full_text) if content_doc else 0
    page_count  = content_doc.page_count if content_doc else 1

    # ── document metadata ─────────────────────────────────────────────────────
    document_metadata: dict[str, Any] = {
        "filename":   filename,
        "scan_id":    scan_id,
        "parser":     parser_type,
        "page_count": page_count,
    }

    # ── entities — clean evidence layer with audit metadata ───────────────────
    entities: list[dict] = []
    confidence_scores: dict[str, float] = {}
    resolved_spans: dict[tuple[str, str], tuple[int, int]] = {}
    for e in resolved_entities:
        if not _is_clean_entity(e.pii_type, e.value):
            continue
        resolved_spans[(e.pii_type, e.value)] = (e.start, e.end)
        entry: dict[str, Any] = {
            "type":       e.pii_type,
            "value":      e.value,
            "confidence": round(e.confidence, 4),
            "source":     e.sources[0] if e.sources else "unknown",
        }
        if e.start >= 0:
            entry["span"] = {"start": e.start, "end": e.end}
        # Audit metadata for compliance traceability
        if hasattr(e, "metadata") and e.metadata:
            entry["audit"] = {
                "engine_count": e.metadata.get("engine_count", 1),
                "grounded": e.metadata.get("grounded", True),
            }
        entities.append(entry)
        confidence_scores[e.pii_type] = max(
            confidence_scores.get(e.pii_type, 0.0), e.confidence
        )
    _assert_output_spans_match_resolved(entities, resolved_spans)

    # ── entity groups (replaces structured_fields) ────────────────────────────
    entity_groups = build_entity_groups(resolved_entities)

    # ── document hints ────────────────────────────────────────────────────────
    document_hints = _build_document_hints(resolved_entities, content_doc)

    # ── ocr ───────────────────────────────────────────────────────────────────
    ocr = _ocr_quality(content_doc, char_count)

    # ── validation ────────────────────────────────────────────────────────────
    if validation_report:
        validation_results: dict[str, Any] = {
            "passed":      validation_report.passed,
            "span_errors": validation_report.span_errors,
        }
    else:
        validation_results = {"passed": True, "span_errors": 0}

    # ── redactions ────────────────────────────────────────────────────────────
    redactions: dict[str, Any] = {
        "map":   redaction_map or {},
        "count": len(redaction_map) if redaction_map else 0,
    }
    if redaction_verification is not None:
        redactions["redaction_verification"] = redaction_verification

    # ── processing metrics ────────────────────────────────────────────────────
    processing_metrics: dict[str, Any] = {
        "total_ms":      round(elapsed_ms, 1),
        "ocr_ms":        round(ocr_ms, 1),
        "detection_ms":  round(detection_ms, 1),
        "resolution_ms": round(resolution_ms, 1),
        "timeouts":      sum(1 for er in engine_results if getattr(er, "error", None) == "timeout"),
    }

    # ── build response ────────────────────────────────────────────────────────
    result: dict[str, Any] = {
        "status":             "success",
        "document_metadata":  document_metadata,
        "entities":           entities,
        "entity_groups":      entity_groups,
        "document_hints":     document_hints,
        "ocr":                ocr,
        "validation_results": validation_results,
        "redactions":         redactions,
        "confidence_scores":  confidence_scores,
        "processing_metrics": processing_metrics,
    }

    # ── debug (opt-in) ────────────────────────────────────────────────────────
    if debug:
        result["debug"] = {
            "engine_timings": [
                {
                    "engine":      er.engine,
                    "matches":     len(er.matches),
                    "duration_ms": round(er.duration_ms, 1),
                    "error":       er.error,
                }
                for er in engine_results
            ],
            "routing_rationale": ingestion_plan.rationale if ingestion_plan else [],
            "language":          language or "unknown",
        }

    return result


def _assert_output_spans_match_resolved(
    output_entities: list[dict[str, Any]],
    resolved_spans: dict[tuple[str, str], tuple[int, int]],
) -> None:
    """Output layer must copy resolver spans, never recompute them."""
    for entity in output_entities:
        span = entity.get("span")
        if not span:
            continue
        expected = resolved_spans.get((entity["type"], entity["value"]))
        if expected is None:
            raise AssertionError("output entity not present in resolved entities")
        if (span["start"], span["end"]) != expected:
            raise AssertionError("output span diverged from resolved span")


def build_error_response(filename: str, error: str) -> dict[str, Any]:
    return {
        "status":   "error",
        "filename": filename,
        "message":  error,
    }
    document: dict[str, Any] = {
        "filename":   filename,
        "scan_id":    scan_id,
        "parser":     parser_type,
        "page_count": page_count,
    }

    # ── entities — clean evidence layer ───────────────────────────────────────
    entities: list[dict] = []
    for e in resolved_entities:
        if not _is_clean_entity(e.pii_type, e.value):
            continue
        entry: dict[str, Any] = {
            "type":       e.pii_type,
            "value":      e.value,
            "confidence": round(e.confidence, 4),
            "source":     e.sources[0] if e.sources else "unknown",
        }
        if e.start >= 0:
            entry["span"] = {"start": e.start, "end": e.end}
        entities.append(entry)

    # ── ocr ───────────────────────────────────────────────────────────────────
    ocr = _ocr_quality(content_doc, char_count)

    # ── validation ────────────────────────────────────────────────────────────
    if validation_report:
        validation: dict[str, Any] = {
            "passed":      validation_report.passed,
            "span_errors": validation_report.span_errors,
        }
    else:
        validation = {"passed": True, "span_errors": 0}

    # ── redaction ─────────────────────────────────────────────────────────────
    redaction: dict[str, Any] = {
        "map":   redaction_map or {},
        "count": len(redaction_map) if redaction_map else 0,
    }

    # ── build response ────────────────────────────────────────────────────────
    result: dict[str, Any] = {
        "status":     "success",
        "document":   document,
        "entities":   entities,
        "ocr":        ocr,
        "validation": validation,
        "redaction":  redaction,
    }

    # ── debug (opt-in) ────────────────────────────────────────────────────────
    if debug:
        total_engine_ms = sum(er.duration_ms for er in engine_results)
        result["debug"] = {
            "total_ms":        round(elapsed_ms, 1),
            "engine_timings":  [
                {
                    "engine":      er.engine,
                    "matches":     len(er.matches),
                    "duration_ms": round(er.duration_ms, 1),
                    "error":       er.error,
                }
                for er in engine_results
            ],
            "routing_rationale": ingestion_plan.rationale if ingestion_plan else [],
            "language":          language or "unknown",
        }
    else:
        # Always include timing at top level for observability
        result["processing_ms"] = round(elapsed_ms, 1)

    return result


def build_error_response(filename: str, error: str) -> dict[str, Any]:
    return {
        "status":   "error",
        "filename": filename,
        "message":  error,
    }
