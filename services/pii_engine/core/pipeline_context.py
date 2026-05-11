"""
Pipeline Context Tracker

Tracks request_id, timing, stages, file metadata, and errors throughout
the pipeline execution. Essential for observability and debugging.

Usage:
    ctx = PipelineContext()
    ctx.set_metadata("filename", "passport.pdf")
    ctx.set_metadata("content_type", "application/pdf")
    
    with ctx.stage("parser"):
        # ... parsing logic ...
        pass
    
    print(f"Total elapsed: {ctx.elapsed()}s")
"""

from __future__ import annotations

import uuid
import time
from dataclasses import dataclass, field
from typing import Any, Optional
from datetime import datetime
import json


@dataclass
class StageMetrics:
    """Metrics for a single pipeline stage."""
    name: str
    started_at: float = 0.0
    ended_at: float = 0.0
    duration_ms: float = 0.0
    status: str = "pending"  # pending, running, success, failed
    input_count: int = 0
    output_count: int = 0
    error: Optional[str] = None
    metadata: dict = field(default_factory=dict)

    @property
    def duration_seconds(self) -> float:
        """Return duration in seconds."""
        return self.duration_ms / 1000

    def to_dict(self) -> dict:
        """Convert to dictionary for JSON serialization."""
        return {
            "name": self.name,
            "duration_ms": round(self.duration_ms, 2),
            "status": self.status,
            "input_count": self.input_count,
            "output_count": self.output_count,
            "error": self.error,
            "metadata": self.metadata,
        }


@dataclass
class PipelineContext:
    """
    Context tracker for a single pipeline execution.
    
    Tracks:
    - request_id: Unique identifier for this pipeline run
    - timing: Start time, end time, stage durations
    - stages: List of all stages executed
    - metadata: File info, parser selected, entity counts
    - errors: Any errors encountered
    
    Usage:
        ctx = PipelineContext()
        ctx.set_file_metadata("report.pdf", "application/pdf", 1024000)
        
        # Track stages
        with ctx.track_stage("parser") as stage:
            text = parser.parse(file_path)
            stage.set_output(len(text))
        
        # Get timing report
        report = ctx.get_stage_report()
    """
    request_id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    started_at: float = field(default_factory=time.time)
    ended_at: Optional[float] = None
    metadata: dict[str, Any] = field(default_factory=dict)
    stages: list[StageMetrics] = field(default_factory=list)
    errors: list[dict] = field(default_factory=list)
    debug_mode: bool = False
    debug_dir: Optional[str] = None

    def __post_init__(self):
        """Initialize debug directory if debug mode is enabled."""
        if self.debug_mode and self.debug_dir:
            import os
            os.makedirs(self.debug_dir, exist_ok=True)

    def elapsed(self) -> float:
        """Return elapsed time in seconds since context was created."""
        end = self.ended_at if self.ended_at else time.time()
        return round(end - self.started_at, 2)

    def set_metadata(self, key: str, value: Any) -> None:
        """Set a metadata key-value pair."""
        self.metadata[key] = value

    def set_file_metadata(self, filename: str, content_type: str, size_bytes: int) -> None:
        """Set standard file metadata."""
        self.metadata["filename"] = filename
        self.metadata["content_type"] = content_type
        self.metadata["size_bytes"] = size_bytes
        self.metadata["extension"] = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""

    def track_stage(self, stage_name: str) -> "StageTracker":
        """
        Create a stage tracker context manager.
        
        Usage:
            with ctx.track_stage("parser") as stage:
                text = parser.parse(file_path)
                stage.set_output(len(text))
        """
        return StageTracker(self, stage_name)

    def add_stage(self, stage: StageMetrics) -> None:
        """Add a completed stage to the context."""
        self.stages.append(stage)

    def record_error(self, stage: str, error: Exception) -> None:
        """Record an error that occurred during execution."""
        self.errors.append({
            "stage": stage,
            "error_type": type(error).__name__,
            "error_message": str(error),
            "timestamp": time.time(),
        })

    def finalize(self) -> None:
        """Mark the context as complete."""
        self.ended_at = time.time()

    def get_stage_report(self) -> dict:
        """Generate a report of all stages."""
        return {
            "request_id": self.request_id,
            "total_elapsed_seconds": self.elapsed(),
            "metadata": self.metadata,
            "stages": [s.to_dict() for s in self.stages],
            "errors": self.errors,
            "success": len(self.errors) == 0,
        }

    def get_timing_summary(self) -> dict[str, float]:
        """Get timing summary for all stages."""
        return {s.name: s.duration_ms for s in self.stages}

    def to_json(self, indent: int = 2) -> str:
        """Serialize context to JSON."""
        return json.dumps(self.get_stage_report(), indent=indent)

    def __str__(self) -> str:
        """String representation showing key metrics."""
        stage_summary = ", ".join(f"{s.name}({s.duration_ms:.0f}ms)" for s in self.stages)
        return (
            f"PipelineContext(request_id={self.request_id}, "
            f"elapsed={self.elapsed()}s, "
            f"stages=[{stage_summary}], "
            f"errors={len(self.errors)})"
        )


class StageTracker:
    """Context manager for tracking a stage's execution."""

    def __init__(self, context: PipelineContext, stage_name: str):
        self.context = context
        self.stage_name = stage_name
        self.stage = StageMetrics(name=stage_name)
        self._start_time: float = 0.0

    def __enter__(self) -> "StageTracker":
        """Enter the stage context."""
        self._start_time = time.time()
        self.stage.started_at = self._start_time
        self.stage.status = "running"
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Exit the stage context."""
        self.stage.ended_at = time.time()
        self.stage.duration_ms = (self.stage.ended_at - self._start_time) * 1000

        if exc_type is not None:
            self.stage.status = "failed"
            self.stage.error = str(exc_val)
            self.context.record_error(self.stage_name, exc_val)
        else:
            self.stage.status = "success"

        self.context.add_stage(self.stage)
        return False  # Don't suppress exceptions

    def set_input(self, count: int, **metadata) -> None:
        """Set input metrics for the stage."""
        self.stage.input_count = count
        self.stage.metadata.update(metadata)

    def set_output(self, count: int, **metadata) -> None:
        """Set output metrics for the stage."""
        self.stage.output_count = count
        self.stage.metadata.update(metadata)

    def add_metadata(self, key: str, value: Any) -> None:
        """Add metadata to the stage."""
        self.stage.metadata[key] = value


# Pre-configured context factory
def create_pipeline_context(debug: bool = False, debug_dir: Optional[str] = None) -> PipelineContext:
    """
    Create a new pipeline context with standard configuration.
    
    Args:
        debug: Enable debug mode for intermediate output dumps
        debug_dir: Directory for debug outputs
    
    Returns:
        Configured PipelineContext instance
    """
    return PipelineContext(debug_mode=debug, debug_dir=debug_dir)


# Global context for the current pipeline execution
# Used when you don't want to pass context through every function
_current_context: Optional[PipelineContext] = None


def get_current_context() -> Optional[PipelineContext]:
    """Get the current pipeline context."""
    return _current_context


def set_current_context(ctx: Optional[PipelineContext]) -> None:
    """Set the current pipeline context."""
    global _current_context
    _current_context = ctx


def reset_current_context() -> None:
    """Reset the current pipeline context."""
    global _current_context
    _current_context = None