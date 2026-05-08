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

    return {
        "status":              "success",
        "document_metadata":   doc_meta,
        "entities":            entities,
        "pii_entities":        pii_entities,
        "redactions":          redactions,
        "confidence_scores":   confidence_scores,
        "processing_metrics":  processing_metrics,
        "validation_results":  validation_results,
    }


def build_error_response(filename: str, error: str) -> dict[str, Any]:
    return {
        "status":  "error",
        "filename": filename,
        "message": error,
    }
