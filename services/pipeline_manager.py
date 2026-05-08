"""
services/pipeline_manager.py
-------------------------------
Global Pipeline Manager — lifecycle, observability, and state.

Responsibilities:
  • Pipeline lifecycle     — task start/end/retry tracking
  • Execution state        — per-request structured log context
  • Observability          — per-engine telemetry + structured JSON logs
  • Memory coordination    — engine load state tracking
  • Concurrency management — concurrent request counting

This is NOT a task queue — it's a per-request context manager that wires
structured logging, timing, and engine activation into every detection run.

Usage:
    with PipelineManager.begin("scan-file", source="invoice.pdf") as ctx:
        result = dispatch_detection(text, ...)
        ctx.record_engines(result.engine_results)
    # On exit, ctx.summary() is logged automatically.
"""

from __future__ import annotations

import logging
import threading
import time
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import Any, Generator, Optional

logger = logging.getLogger(__name__)


@dataclass
class TaskContext:
    """Per-request pipeline state."""
    task_id:     str
    source:      str
    start_time:  float = field(default_factory=time.perf_counter)
    engine_logs: list[dict] = field(default_factory=list)
    extra:       dict = field(default_factory=dict)

    # ── Observability ─────────────────────────────────────────────────────────

    def record_engines(self, engine_results) -> None:
        """Log per-engine telemetry from EngineResult objects."""
        for er in engine_results:
            entry = {
                "engine":      er.engine.upper(),
                "matches":     len(er.matches),
                "duration_ms": round(er.duration_ms, 1),
                "error":       er.error,
            }
            self.engine_logs.append(entry)
            if er.error:
                logger.warning(
                    "[%s] ERROR: %s", er.engine.upper(), er.error
                )
            else:
                logger.info(
                    "[%s] matches=%d  duration=%.0f ms",
                    er.engine.upper(), len(er.matches), er.duration_ms,
                )

    def summary(self) -> dict:
        """Return a structured summary dict for JSON logging."""
        elapsed_ms = round((time.perf_counter() - self.start_time) * 1000, 1)
        total_matches = sum(e.get("matches", 0) for e in self.engine_logs)
        return {
            "task_id":       self.task_id,
            "source":        self.source,
            "elapsed_ms":    elapsed_ms,
            "total_matches": total_matches,
            "engines":       self.engine_logs,
            **self.extra,
        }

    def log_summary(self) -> None:
        s = self.summary()
        logger.info(
            "[PIPELINE] task=%s source=%s elapsed=%.0f ms total_matches=%d engines=%s",
            s["task_id"], s["source"], s["elapsed_ms"], s["total_matches"],
            [f"{e['engine']}={e['matches']}" for e in s["engines"]],
        )


class PipelineManager:
    """
    Singleton pipeline lifecycle manager.

    Thread-safe: each request gets an isolated TaskContext.
    Tracks active request count for observability.
    """

    _instance: Optional["PipelineManager"] = None
    _lock = threading.Lock()

    def __init__(self):
        self._active_count = 0
        self._total_count  = 0
        self._engine_load_state: dict[str, bool] = {}

    @classmethod
    def get(cls) -> "PipelineManager":
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = cls()
        return cls._instance

    @contextmanager
    def begin(
        self,
        task_id: str,
        source: str = "",
        **extra: Any,
    ) -> Generator[TaskContext, None, None]:
        """
        Context manager for a detection pipeline run.

        On entry:  creates TaskContext, increments active count, logs start.
        On exit:   logs summary, decrements active count.

        Example:
            with PipelineManager.get().begin("scan-file", source="doc.pdf") as ctx:
                result = dispatch_detection(text)
                ctx.record_engines(result.engine_results)
        """
        ctx = TaskContext(task_id=task_id, source=source, extra=extra)
        with self._lock:
            self._active_count += 1
            self._total_count  += 1

        logger.info(
            "[PIPELINE] START task=%s source=%s | active=%d total=%d",
            task_id, source or "unknown",
            self._active_count, self._total_count,
        )

        try:
            yield ctx
        finally:
            ctx.log_summary()
            with self._lock:
                self._active_count -= 1

    def mark_engine_loaded(self, engine_name: str) -> None:
        with self._lock:
            self._engine_load_state[engine_name] = True
        logger.info("[PIPELINE] Engine ready: %s", engine_name.upper())

    def engine_status(self) -> dict[str, bool]:
        with self._lock:
            return dict(self._engine_load_state)

    @property
    def active_requests(self) -> int:
        return self._active_count

    @property
    def total_requests(self) -> int:
        return self._total_count


# Convenience accessor
def get_pipeline() -> PipelineManager:
    return PipelineManager.get()
