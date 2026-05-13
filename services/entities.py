"""
services/entities.py
--------------------
Canonical entity types used across ALL engines and pipeline stages.

Every engine MUST emit PIIMatch.
The resolver MUST emit ResolvedEntity.
No custom variants allowed.

This is the ONE source of truth for entity shapes.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


@dataclass
class PIIMatch:
    """
    A single PII detection from any engine.

    ALL engines MUST emit this exact object.
    No custom variants. No extra fields.
    If you need engine-specific data, put it in metadata.
    """
    pii_type: str           # e.g. "aadhaar", "name", "diagnosis"
    value: str              # the matched text value
    start: int              # span start in NORMALISED text coordinates
    end: int                # span end in NORMALISED text coordinates
    confidence: float       # 0.0 - 1.0
    source: str             # "regex" | "gliner" | "qwen_ner"
    context: str = ""       # surrounding snippet for audit
    metadata: dict = field(default_factory=dict)

    def __post_init__(self):
        # Ensure confidence is bounded
        if self.confidence < 0.0:
            self.confidence = 0.0
        elif self.confidence > 1.0:
            self.confidence = 1.0


@dataclass
class ResolvedEntity:
    """
    A deduplicated, fused entity from the resolver.

    This is what the rest of the pipeline works with:
    post-processor, validator, redaction engine, output schema.
    """
    pii_type: str
    value: str
    confidence: float
    sources: list[str] = field(default_factory=list)
    start: int = -1
    end: int = -1
    context: str = ""
    sensitivity: str = "High"
    metadata: dict = field(default_factory=dict)

    # Bounding box (images only, set by bbox_mapper)
    bbox: Optional[dict] = None  # {"x": int, "y": int, "w": int, "h": int}

    def __post_init__(self):
        if self.confidence < 0.0:
            self.confidence = 0.0
        elif self.confidence > 1.0:
            self.confidence = 1.0


# ── Sensitivity levels ───────────────────────────────────────────────────────

class Sensitivity:
    VERY_HIGH = "Very High"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"


# ── Engine source constants ──────────────────────────────────────────────────

class EngineSource:
    REGEX = "regex"
    GLINER = "gliner"
    QWEN_NER = "qwen_ner"
    LLM = "llm"  # legacy, not routed
