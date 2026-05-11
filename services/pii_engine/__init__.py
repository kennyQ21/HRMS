"""
PII Engine Module

Enterprise-grade PII detection pipeline with observability.

Components:
- core: Pipeline context and stage tracking
- utils: Logging, stage decorators, debug dumping
- validation: Output schema validation

Usage:
    from services.pii_engine import PipelineContext, DebugDumper
    from services.pii_engine.validation import validate_output
"""

from .core import (
    PipelineContext,
    StageMetrics,
    StageTracker,
    create_pipeline_context,
)
from .utils import (
    setup_logger,
    get_logger,
    DebugDumper,
)
from .validation import validate_output, ValidationResult
from .pipeline_runner import run_pipeline, PipelineResult, get_pipeline_metrics

__all__ = [
    # Core
    "PipelineContext",
    "StageMetrics",
    "StageTracker",
    "create_pipeline_context",
    # Utils
    "setup_logger",
    "get_logger",
    "DebugDumper",
    # Validation
    "validate_output",
    "ValidationResult",
    # Pipeline
    "run_pipeline",
    "PipelineResult",
    "get_pipeline_metrics",
]
