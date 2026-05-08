"""
services/engines/base_engine.py
--------------------------------
Abstract base class that every detection engine must implement.

Each engine receives normalised text and returns a list of PIIMatch objects.
The Detection Dispatcher calls all engines, then passes their combined output
to the Entity Resolution Layer for merging and deduplication.
"""

from __future__ import annotations

import logging
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class PIIMatch:
    """A single PII entity found by any detection engine."""
    pii_type:   str           # MASTER_PIIS id — e.g. "aadhaar", "diagnosis"
    value:      str           # matched / extracted text
    source:     str           # engine name — "regex" | "gliner" | "llm" | "otter" | "presidio"
    confidence: float         # 0.0 – 1.0
    start:      int = -1      # character offset in normalised text (-1 = unknown)
    end:        int = -1
    context:    str = ""      # surrounding snippet for audit / LLM explanation
    metadata:   dict = field(default_factory=dict)  # engine-specific extras


@dataclass
class EngineResult:
    """Structured output returned by every engine after a detection run."""
    engine:     str
    matches:    list[PIIMatch] = field(default_factory=list)
    duration_ms: float = 0.0
    error:      str | None = None

    @property
    def counts(self) -> dict[str, int]:
        out: dict[str, int] = {}
        for m in self.matches:
            out[m.pii_type] = out.get(m.pii_type, 0) + 1
        return out


class BaseEngine(ABC):
    """
    All detection engines must subclass this and implement `detect`.

    Engines are designed to be stateless per call — model weights are lazily
    loaded once per process via @functools.lru_cache in each subclass.
    """

    name: str = "base"

    def run(self, text: str, **kwargs: Any) -> EngineResult:
        """
        Public entry point.  Times the run, catches exceptions so a single
        engine failure doesn't abort the whole detection pipeline.
        """
        start = time.perf_counter()
        try:
            matches = self.detect(text, **kwargs)
            duration = (time.perf_counter() - start) * 1000
            logger.info(
                "[%s] detected %d entities in %.1f ms",
                self.name.upper(), len(matches), duration,
            )
            return EngineResult(engine=self.name, matches=matches, duration_ms=duration)
        except Exception as exc:
            duration = (time.perf_counter() - start) * 1000
            logger.error("[%s] engine error: %s", self.name.upper(), exc, exc_info=True)
            return EngineResult(engine=self.name, matches=[], duration_ms=duration, error=str(exc))

    @abstractmethod
    def detect(self, text: str, **kwargs: Any) -> list[PIIMatch]:
        """
        Core detection logic.  Must return a list of PIIMatch objects.
        The implementation should NOT catch every exception — let BaseEngine.run
        handle that so errors are logged uniformly.
        """
        ...
