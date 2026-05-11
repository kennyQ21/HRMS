"""
services/output_schema.py
---------------------------
Unified JSON Output Schema.

Produces the final structured response for every file scan:

{
  "document_metadata":   { filename, size, page_count, doc_type, ... },
  "entities":            [ { type, value, confidence, source, span, context }, ... ],
  "pii_entities":        { pii_type: [ { value, confidence, sources }, ... ] },
  "redactions":          [ { pii_type, original, replacement, span }, ... ],
  "confidence_scores":   { pii_type: avg_confidence },
  "processing_metrics":  { total_ms, engines_used, block_count, ocr_used, ... },
  "validation_results":  { passed, issues, coverage, ... }
}
"""

from __future__ import annotations

import time
from typing import Any, Optional


def build_scan_response(
    scan_id: int,
    filename: str,
    resolved_entities: list,          # list[ResolvedEntity]
    engine_results: list,             # list[EngineResult]
    content_doc,                      # ContentDocument | None
    ingestion_plan,                   # IngestionPlan | None
    validation_report = None,         # ValidationReport | None
    redaction_map: Optional[dict] = None,
    elapsed_ms: float = 0.0,
) -> dict[str, Any]:
    """
    Assemble the complete unified JSON response for one file scan.

    This is the canonical output shape consumed by:
      - /scan-file endpoint (returned directly)
      - /get-scan-results endpoint (stored and re-served)
    """

    # ── document_metadata ─────────────────────────────────────────────────────
    doc_meta: dict[str, Any] = {
        "scan_id":    scan_id,
        "filename":   filename,
    }
    if ingestion_plan:
        doc_meta.update({
            "doc_type":     ingestion_plan.doc_type,
            "parser_type":  ingestion_plan.parser_type,
            "needs_ocr":    ingestion_plan.needs_ocr,
            "chunking_mode": ingestion_plan.chunking_mode,
            "is_structured": ingestion_plan.is_structured,
            "routing_rationale": ingestion_plan.rationale,
        })
    if content_doc:
        doc_meta.update({
            "page_count":   content_doc.page_count,
            "block_count":  len(content_doc.blocks),
            "has_tables":   content_doc.has_tables,
            "char_count":   len(content_doc.full_text),
        })

    # ── entities — flat list ──────────────────────────────────────────────────
    entities: list[dict] = []
    for e in resolved_entities:
        entities.append({
            "pii_type":   e.pii_type,
            "value":      e.value,
            "confidence": round(e.confidence, 4),
            "sources":    e.sources,
            "sensitivity": e.sensitivity,
            "span":       {"start": e.start, "end": e.end}
                          if e.start >= 0 else None,
            "context":    e.context or None,
        })

    # ── pii_entities — grouped by type ───────────────────────────────────────
    pii_entities: dict[str, list[dict]] = {}
    for e in resolved_entities:
        entry = {
            "value":      e.value,
            "confidence": round(e.confidence, 4),
            "sources":    e.sources,
        }
        pii_entities.setdefault(e.pii_type, []).append(entry)

    # ── redactions ────────────────────────────────────────────────────────────
    redactions: list[dict] = []
    if redaction_map:
        # Build a redaction record per resolved entity
        for e in resolved_entities:
            replacement = redaction_map.get(e.value)
            if replacement:
                redactions.append({
                    "pii_type":    e.pii_type,
                    "original":    e.value,
                    "replacement": replacement,
                    "span": {"start": e.start, "end": e.end}
                            if e.start >= 0 else None,
                })

    # ── confidence_scores — average per pii_type ─────────────────────────────
    confidence_scores: dict[str, float] = {}
    type_confs: dict[str, list[float]] = {}
    for e in resolved_entities:
        type_confs.setdefault(e.pii_type, []).append(e.confidence)
    for pii_type, confs in type_confs.items():
        confidence_scores[pii_type] = round(sum(confs) / len(confs), 4)

    # ── processing_metrics ────────────────────────────────────────────────────
    engines_used: list[str] = []
    engine_details: list[dict] = []
    total_engine_ms = 0.0
    for er in engine_results:
        if er.matches or not er.error:
            engines_used.append(er.engine)
        engine_details.append({
            "engine":    er.engine,
            "matches":   len(er.matches),
            "duration_ms": round(er.duration_ms, 1),
            "error":     er.error,
        })
        total_engine_ms += er.duration_ms

    processing_metrics: dict[str, Any] = {
        "total_ms":          round(elapsed_ms, 1),
        "engine_total_ms":   round(total_engine_ms, 1),
        "engines_used":      engines_used,
        "engine_details":    engine_details,
        "entity_count":      len(resolved_entities),
        "redaction_count":   len(redactions),
    }
    if content_doc:
        processing_metrics["ocr_used"] = any(
            b.source == "ocr" for b in content_doc.blocks
        )

    # ── validation_results ────────────────────────────────────────────────────
    validation_results: dict[str, Any] = {"passed": True, "issues": []}
    if validation_report:
        validation_results = validation_report.summary()

    # ── structured_fields — for identity documents ────────────────────────────
    # When the document is a known identity card type, extract a clean key-value
    # map of the most important fields for downstream compliance workflows.
    doc_type = doc_meta.get("doc_type", "generic")
    structured_fields = _build_structured_fields(doc_type, resolved_entities)

    result: dict[str, Any] = {
        "status":              "success",
        "document_metadata":   doc_meta,
        "entities":            entities,
        "pii_entities":        pii_entities,
        "redactions":          redactions,
        "confidence_scores":   confidence_scores,
        "processing_metrics":  processing_metrics,
        "validation_results":  validation_results,
    }
    if structured_fields:
        result["structured_fields"] = structured_fields

    return result


# ── Identity document structured field extractor ──────────────────────────────

_ID_DOC_TYPES = {
    "aadhaar_card":    ["name", "dob", "gender", "aadhaar", "address", "pincode"],
    "pan_card":        ["name", "dob", "pan"],
    "passport":        ["name", "dob", "gender", "passport", "nationality", "address"],
    "voter_id":        ["name", "dob", "gender", "voter_id", "address"],
    "driving_license": ["name", "dob", "gender", "driving_license", "address"],
    "id":              ["name", "dob", "aadhaar", "pan", "passport", "voter_id", "driving_license"],
}


def _build_structured_fields(
    doc_type: str,
    resolved_entities: list,
) -> dict[str, Any]:
    """
    For identity documents, produce a clean structured key-value map.
    Only populated when doc_type is a known identity card type.
    """
    wanted_types = _ID_DOC_TYPES.get(doc_type)
    if not wanted_types:
        return {}

    fields: dict[str, Any] = {"document_type": doc_type}
    by_type: dict[str, list] = {}
    for e in resolved_entities:
        by_type.setdefault(e.pii_type, []).append(e)

    for ptype in wanted_types:
        items = by_type.get(ptype, [])
        if not items:
            continue
        # Pick highest-confidence value
        best = max(items, key=lambda e: e.confidence)
        fields[ptype] = {
            "value":      best.value,
            "confidence": round(best.confidence, 3),
        }

    return fields


def build_error_response(filename: str, error: str) -> dict[str, Any]:
    return {
        "status":  "error",
        "filename": filename,
        "message": error,
    }
