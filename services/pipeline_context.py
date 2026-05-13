"""
services/pipeline_context.py
-----------------------------
Single shared context object that flows through the entire pipeline.

Eliminates:
  - parameter explosion across function signatures
  - duplicated metadata passing
  - inconsistent state between stages

This is NOT an orchestration framework.
It is a simple data container.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Optional

from services.ingestion_dispatcher import DocumentProfile, IngestionPlan
from services.language_detector import LangResult
from services.text_normalizer import NormalisedText  # canonical span coordinate system


@dataclass
class ContentDocument:
    """Parsed document structure."""
    full_text: str = ""
    blocks: list[dict] = field(default_factory=list)
    page_count: int = 1
    ocr_output: Optional[list[dict]] = None


@dataclass
class EngineResult:
    """Output from a single detection engine."""
    engine: str
    matches: list = field(default_factory=list)  # list[PIIMatch]
    elapsed_ms: float = 0.0
    error: Optional[str] = None


@dataclass
class ValidationReport:
    """Result of span validation."""
    passed: bool = True
    issues: list[str] = field(default_factory=list)
    span_errors: int = 0


@dataclass
class ProcessingMetrics:
    """Timing and operational metrics for the scan."""
    stages: dict[str, float] = field(default_factory=dict)   # stage_name → elapsed_ms
    engine_timings: list[dict] = field(default_factory=list)  # [{engine, matches, ms}]
    timeouts: int = 0
    total_ms: float = 0.0
    language: str = "en"
    dominant_script: str = "latin"


@dataclass
class PipelineContext:
    """
    ONE context object that flows through the entire pipeline.

    Stages READ from and WRITE to this object.
    No stage reaches into another stage's internals.
    """
    # ── Input ────────────────────────────────────────────────────────────────
    file_path: str = ""
    filename: str = ""
    file_bytes: Optional[bytes] = None
    password: Optional[str] = None

    # ── Ingestion ────────────────────────────────────────────────────────────
    ingestion_plan: Optional[IngestionPlan] = None
    document_profile: Optional[DocumentProfile] = None

    # ── Parsing ──────────────────────────────────────────────────────────────
    parsed_data: Optional[dict] = None
    content_document: Optional[ContentDocument] = None
    is_image: bool = False

    # ── Normalization ────────────────────────────────────────────────────────
    normalized_text: Optional[NormalisedText] = None

    # ── Language ─────────────────────────────────────────────────────────────
    language_result: Optional[LangResult] = None

    # ── Detection ────────────────────────────────────────────────────────────
    engine_results: list[EngineResult] = field(default_factory=list)

    # ── Resolution ───────────────────────────────────────────────────────────
    resolved_entities: list = field(default_factory=list)  # list[ResolvedEntity]

    # ── Validation ───────────────────────────────────────────────────────────
    validation_report: Optional[ValidationReport] = None
    validation_report_ocr: Any = None  # OCRValidationReport (images only)

    # ── Metrics ──────────────────────────────────────────────────────────────
    metrics: ProcessingMetrics = field(default_factory=ProcessingMetrics)

    # ── Warnings ─────────────────────────────────────────────────────────────
    warnings: list[str] = field(default_factory=list)
    partial_scan: bool = False

    # ── Internal timing ──────────────────────────────────────────────────────
    _t0: float = field(default_factory=time.perf_counter)
    _stage_t: float = field(default_factory=time.perf_counter)

    def mark_stage(self, name: str) -> None:
        """Record timing for a completed stage."""
        now = time.perf_counter()
        elapsed_ms = (now - self._stage_t) * 1000
        self.metrics.stages[name] = round(elapsed_ms, 1)
        self._stage_t = now

    def add_warning(self, msg: str) -> None:
        """Append an operational warning."""
        self.warnings.append(msg)

    def finalize(self) -> None:
        """Compute total elapsed time."""
        self.metrics.total_ms = round((time.perf_counter() - self._t0) * 1000, 1)
