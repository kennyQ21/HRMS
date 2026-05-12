"""
services/output_schema.py
---------------------------
Document-centric canonical output schema.

Philosophy
──────────
The response is structured around the DOCUMENT, not the engines.
Consumers get stable, clean, business-ready data.
Internal extraction artifacts (engine timings, GLiNER fragments,
OCR block lists) live in `debug` and are excluded from the default response.

Schema
──────
{
  "status":           "success" | "error",

  "document": {
    "type":           "aadhaar_card" | "pan_card" | "passport" | "generic" | …,
    "confidence":     0.0–1.0,
    "filename":       "…",
    "scan_id":        1,
    "parser":         "image" | "pdf" | "docx" | …,
    "page_count":     1
  },

  "structured_fields": {          ← stable API contract, doc-type specific
    "aadhaar_number": { "value": "…", "confidence": 0.99 },
    "address": {
      "full": "…",
      "city": "…",
      "state": "…",
      "postal_code": "…"
    },
    …
  },

  "entities": [                   ← evidence layer — one object per detected entity
    {
      "type": "aadhaar",
      "value": "…",
      "confidence": 1.0,
      "source": "regex",
      "span": { "start": 0, "end": 12 }
    },
    …
  ],

  "ocr": {
    "used": true,
    "quality": { "char_count": 868, "manual_review_required": false }
  },

  "validation": { "passed": true, "span_errors": 0 },

  "redaction": { "map": {…}, "count": 0 },

  "debug": {                      ← omitted unless debug=True is requested
    "engine_timings": […],
    "routing_rationale": […],
    "language": "en"
  }
}
"""

from __future__ import annotations

import re
from typing import Any, Optional


# ── Entity quality filter ─────────────────────────────────────────────────────
# Entities that pass detection but are too generic/noisy for the final output.

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
    # Generic nationality strings that add no value
    if ptype == "nationality" and v.lower() in _NATIONALITY_JUNK:
        return False
    # Minimum length per type
    if len(v) < _MIN_VALUE_LEN.get(ptype, 2):
        return False
    # Address fragments that are pure uppercase noise or very short
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
    """
    Merge multiple address fragment entities into one structured address.
    Sorts fragments by span position (where known) and joins cleanly.
    """
    clean = [
        e for e in address_entities
        if _is_clean_entity("address", e.value)
        and len(e.value) > 5
    ]
    if not clean:
        return {}

    # Sort by span start where available, else keep as-is
    clean.sort(key=lambda e: e.start if e.start >= 0 else 9999)

    # Build full address string
    parts = []
    seen: set[str] = set()
    for e in clean:
        v = e.value.strip().rstrip(",").strip()
        # Deduplicate
        key = re.sub(r"\s+", " ", v).lower()
        if key not in seen:
            seen.add(key)
            parts.append(v)

    full = ", ".join(parts)

    # Try to extract structured sub-fields
    result: dict[str, Any] = {"full": full}
    full_lower = full.lower()

    # Postal code
    pin = _PINCODE_RE.search(full)
    if pin:
        result["postal_code"] = pin.group(1)

    # State
    for state_lower, state_proper in _STATE_CODES.items():
        if state_lower in full_lower:
            result["state"] = state_proper
            break

    # City
    for city in _CITY_NAMES:
        if city in full_lower:
            result["city"] = city.title()
            break

    return result


# ── Document type confidence ──────────────────────────────────────────────────

_DOC_TYPE_CONFIDENCE: dict[str, float] = {
    "aadhaar_card":    0.97,
    "pan_card":        0.97,
    "passport":        0.95,
    "voter_id":        0.95,
    "driving_license": 0.93,
    "medical":         0.88,
    "financial":       0.85,
    "hr":              0.80,
    "id":              0.75,
    "generic":         0.50,
}


# ── Structured field maps ─────────────────────────────────────────────────────

_DOC_TYPE_FIELDS: dict[str, list[str]] = {
    "aadhaar_card":    ["name", "dob", "gender", "aadhaar", "address", "pincode", "phone"],
    "pan_card":        ["name", "dob", "pan", "gender"],
    "passport":        ["name", "dob", "gender", "passport", "nationality", "address"],
    "voter_id":        ["name", "dob", "gender", "voter_id", "address"],
    "driving_license": ["name", "dob", "gender", "driving_license", "address", "blood_group"],
    "medical":         ["name", "dob", "phone", "email", "mrn", "diagnosis",
                        "allergies", "prescription", "blood_group", "insurance_policy"],
    "financial":       ["name", "phone", "email", "pan", "bank_account", "ifsc", "upi"],
    "hr":              ["name", "email", "phone", "address", "employee_id", "occupation"],
    "id":              ["name", "dob", "aadhaar", "pan", "passport", "voter_id", "driving_license"],
}


def _build_structured_fields(
    doc_type: str,
    resolved_entities: list,
) -> dict[str, Any]:
    """
    Build clean, consumer-facing structured field map for a document.

    Address entities are consolidated. OCR garbage is filtered.
    Only high-confidence, semantically valid values are included.
    """
    wanted = _DOC_TYPE_FIELDS.get(doc_type)
    if not wanted:
        return {}

    by_type: dict[str, list] = {}
    for e in resolved_entities:
        by_type.setdefault(e.pii_type, []).append(e)

    fields: dict[str, Any] = {}

    for ptype in wanted:
        items = by_type.get(ptype, [])
        if not items:
            continue

        if ptype == "address":
            addr = _consolidate_address(items)
            if addr:
                fields["address"] = addr
            continue

        # Pick highest-confidence clean value
        clean = [
            e for e in items
            if _is_clean_entity(ptype, e.value)
        ]
        if not clean:
            continue
        best = max(clean, key=lambda e: e.confidence)

        # Rename to user-friendly keys
        key = {
            "aadhaar": "aadhaar_number",
            "pan":     "pan_number",
            "dob":     "date_of_birth",
            "mrn":     "medical_record_number",
        }.get(ptype, ptype)

        fields[key] = {
            "value":      best.value,
            "confidence": round(best.confidence, 3),
        }

    return fields


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
    elapsed_ms: float = 0.0,
    language: Optional[str] = None,
    debug: bool = False,
) -> dict[str, Any]:
    """
    Assemble the canonical document-centric JSON response.
    """
    doc_type    = ingestion_plan.doc_type if ingestion_plan else "generic"
    parser_type = ingestion_plan.parser_type if ingestion_plan else "unknown"
    char_count  = len(content_doc.full_text) if content_doc else 0
    page_count  = content_doc.page_count if content_doc else 1

    # ── document ──────────────────────────────────────────────────────────────
    document: dict[str, Any] = {
        "type":       doc_type,
        "confidence": _DOC_TYPE_CONFIDENCE.get(doc_type, 0.5),
        "filename":   filename,
        "scan_id":    scan_id,
        "parser":     parser_type,
        "page_count": page_count,
    }

    # ── structured_fields ─────────────────────────────────────────────────────
    structured_fields = _build_structured_fields(doc_type, resolved_entities)

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
        "status":           "success",
        "document":         document,
        "structured_fields": structured_fields,
        "entities":         entities,
        "ocr":              ocr,
        "validation":       validation,
        "redaction":        redaction,
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
