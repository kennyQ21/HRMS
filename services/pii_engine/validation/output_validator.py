"""
Output Validation Layer

Validates pipeline output against strict JSON schema to ensure:
- All required fields present
- Span offsets are valid
- Confidence scores in range
- Entity types are recognized
- Deduplication was performed
- Source parser is tracked
- Metadata is included

Usage:
    from services.pii_engine.validation.output_validator import validate_output
    
    try:
        validate_output(result)
    except ValidationError as e:
        print(f"Invalid output: {e}")
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Set
import re


class ValidationError(Exception):
    """Raised when output validation fails."""
    
    def __init__(self, message: str, field: Optional[str] = None, value: Any = None):
        self.message = message
        self.field = field
        self.value = value
        super().__init__(self.message)
    
    def __str__(self) -> str:
        if self.field:
            return f"Validation error at '{self.field}': {self.message}"
        return f"Validation error: {self.message}"


class ValidationWarning:
    """Non-fatal validation warning."""
    
    def __init__(self, message: str, field: Optional[str] = None, value: Any = None):
        self.message = message
        self.field = field
        self.value = value
    
    def __str__(self) -> str:
        if self.field:
            return f"Warning at '{self.field}': {self.message}"
        return f"Warning: {self.message}"


# Valid PII entity types (internal and display names)
VALID_ENTITY_TYPES: Set[str] = {
    # Internal names
    "email", "phone", "aadhaar", "pan", "voter_id",
    "credit_card", "name", "address", "dob",
    "expiry", "cvv", "ip_address",
    # Entity type names
    "EMAIL", "PHONE_NUMBER", "AADHAAR", "PAN", "VOTER_ID",
    "CREDIT_CARD", "PERSON", "LOCATION", "DOB",
    "EXPIRY", "CVV", "IP_ADDRESS",
}


@dataclass
class ValidationResult:
    """Result of validation including errors and warnings."""
    
    valid: bool
    errors: List[ValidationError] = field(default_factory=list)
    warnings: List[ValidationWarning] = field(default_factory=list)
    
    def add_error(self, message: str, field: Optional[str] = None, value: Any = None):
        self.errors.append(ValidationError(message, field, value))
        self.valid = False
    
    def add_warning(self, message: str, field: Optional[str] = None, value: Any = None):
        self.warnings.append(ValidationWarning(message, field, value))
    
    def merge(self, other: "ValidationResult") -> None:
        """Merge another validation result into this one."""
        self.errors.extend(other.errors)
        self.warnings.extend(other.warnings)
        if other.errors:
            self.valid = False
    
    def to_dict(self) -> dict:
        return {
            "valid": self.valid,
            "errors": [{"message": e.message, "field": e.field} for e in self.errors],
            "warnings": [{"message": w.message, "field": w.field} for w in self.warnings],
        }


def validate_entity_type(entity_type: str, result: ValidationResult) -> bool:
    """Validate that entity type is recognized."""
    if not entity_type:
        result.add_error("Entity type is empty", "type")
        return False
    
    et_upper = entity_type.upper()
    if entity_type not in VALID_ENTITY_TYPES and et_upper not in VALID_ENTITY_TYPES:
        result.add_error(
            f"Unknown entity type: {entity_type}",
            "type",
            entity_type
        )
        return False
    return True


def validate_span_offsets(entity: Dict, text_length: int, result: ValidationResult, index: int) -> bool:
    """Validate span offsets are within bounds."""
    start = entity.get("start", -1)
    end = entity.get("end", -1)
    
    valid = True
    
    # Check start offset
    if start < 0:
        result.add_error(
            f"Entity {index}: invalid start offset {start} (must be >= 0)",
            f"entities[{index}].start",
            start
        )
        valid = False
    elif text_length > 0 and start > text_length:
        result.add_warning(
            f"Entity {index}: start offset {start} exceeds text length {text_length}",
            f"entities[{index}].start",
            start
        )
    
    # Check end offset
    if end < 0:
        result.add_error(
            f"Entity {index}: invalid end offset {end} (must be >= 0)",
            f"entities[{index}].end",
            end
        )
        valid = False
    elif text_length > 0 and end > text_length:
        result.add_warning(
            f"Entity {index}: end offset {end} exceeds text length {text_length}",
            f"entities[{index}].end",
            end
        )
    
    # Check span ordering
    if start >= 0 and end >= 0 and start > end:
        result.add_error(
            f"Entity {index}: start {start} > end {end}",
            f"entities[{index}]",
            {"start": start, "end": end}
        )
        valid = False
    
    return valid


def validate_confidence_score(entity: Dict, result: ValidationResult, index: int) -> bool:
    """Validate confidence score is in valid range."""
    score = entity.get("score", entity.get("confidence"))
    
    if score is None:
        result.add_warning(
            f"Entity {index}: missing confidence score",
            f"entities[{index}].score"
        )
        return True  # Warning, not error
    
    try:
        score_float = float(score)
        if not (0.0 <= score_float <= 1.0):
            result.add_error(
                f"Entity {index}: confidence {score_float} out of range [0, 1]",
                f"entities[{index}].score",
                score_float
            )
            return False
    except (TypeError, ValueError):
        result.add_error(
            f"Entity {index}: confidence '{score}' is not a number",
            f"entities[{index}].score",
            score
        )
        return False
    
    return True


def validate_entity_value(entity: Dict, result: ValidationResult, index: int) -> bool:
    """Validate entity value is present and non-empty."""
    value = entity.get("value")
    
    if value is None:
        result.add_error(
            f"Entity {index}: missing value",
            f"entities[{index}].value"
        )
        return False
    
    if not isinstance(value, str):
        result.add_error(
            f"Entity {index}: value must be string, got {type(value).__name__}",
            f"entities[{index}].value",
            value
        )
        return False
    
    if not value.strip():
        result.add_warning(
            f"Entity {index}: empty value",
            f"entities[{index}].value"
        )
    
    return True


def validate_deduplication(entities: List[Dict], result: ValidationResult) -> bool:
    """Check for duplicate entities (same type and value)."""
    seen: Dict[tuple, int] = {}
    duplicates = []
    
    for i, entity in enumerate(entities):
        entity_type = entity.get("type", "")
        value = entity.get("value", "")
        key = (entity_type, value.lower().strip())
        
        if key in seen:
            duplicates.append((i, seen[key], entity))
        else:
            seen[key] = i
    
    if duplicates:
        for dup_idx, orig_idx, entity in duplicates[:5]:  # Show first 5
            result.add_warning(
                f"Entity {dup_idx} is duplicate of entity {orig_idx}",
                f"entities[{dup_idx}]",
                entity
            )
        if len(duplicates) > 5:
            result.add_warning(
                f"... and {len(duplicates) - 5} more duplicates",
                "entities"
            )
        return False
    
    return True


def validate_overlap(entities: List[Dict], result: ValidationResult) -> bool:
    """Check for overlapping spans of same type."""
    # Group by type
    by_type: Dict[str, List[tuple]] = {}
    for i, entity in enumerate(entities):
        etype = entity.get("type", "UNKNOWN")
        start = entity.get("start", -1)
        end = entity.get("end", -1)
        if start >= 0 and end >= 0:
            by_type.setdefault(etype, []).append((start, end, i))
    
    overlaps = []
    for etype, spans in by_type.items():
        # Sort by start
        spans.sort()
        for i in range(len(spans) - 1):
            if spans[i][1] > spans[i + 1][0]:  # Overlap
                overlaps.append((etype, spans[i], spans[i + 1]))
    
    if overlaps:
        for etype, span1, span2 in overlaps[:5]:
            result.add_warning(
                f"Overlapping {etype} spans: [{span1[0]}:{span1[1]}] and [{span2[0]}:{span2[1]}]",
                f"entities[{span1[2]}] and entities[{span2[2]}]"
            )
        return False
    
    return True


def validate_source_parser(entity: Dict, result: ValidationResult, index: int) -> bool:
    """Validate source parser field."""
    source = entity.get("source")
    
    if source is None:
        # Allow missing source, but warn
        result.add_warning(
            f"Entity {index}: missing source parser",
            f"entities[{index}].source"
        )
        return True
    
    valid_sources = {"regex", "presidio", "ner", "ocr"}
    if source not in valid_sources:
        result.add_warning(
            f"Entity {index}: unknown source '{source}' (expected: {valid_sources})",
            f"entities[{index}].source",
            source
        )
    
    return True


def validate_metadata(output: Dict, result: ValidationResult) -> bool:
    """Validate metadata field."""
    if "metadata" not in output:
        result.add_warning("Missing metadata field")
        return False
    
    metadata = output.get("metadata", {})
    if not isinstance(metadata, dict):
        result.add_error("metadata must be a dict", "metadata")
        return False
    
    # Check for recommended fields
    recommended = ["parser", "text_length", "language"]
    for field in recommended:
        if field not in metadata:
            result.add_warning(f"metadata missing recommended field '{field}'", "metadata")
    
    return True


def validate_output_schema(output: Dict) -> ValidationResult:
    """
    Validate the JSON schema of the pipeline output.
    
    Required fields:
    - entities: list of detected entities
    
    Per-entity fields:
    - type: entity type (EMAIL, PHONE, etc.)
    - value: matched text
    - start: start offset (optional for some sources)
    - end: end offset (optional)
    - score/confidence: detection confidence
    - source: detection method (regex, presidio, etc.)
    """
    result = ValidationResult(valid=True)
    
    # Check root type
    if not isinstance(output, dict):
        result.add_error("Output must be a dict", "root")
        return result
    
    # Check entities field
    if "entities" not in output:
        result.add_error("Missing required field 'entities'", "entities")
        return result
    
    entities = output.get("entities")
    if not isinstance(entities, list):
        result.add_error("'entities' must be a list", "entities")
        return result
    
    # Validate metadata
    validate_metadata(output, result)
    
    # Get text length for span validation
    text_length = output.get("metadata", {}).get("text_length", 0)
    
    # Validate each entity
    for i, entity in enumerate(entities):
        if not isinstance(entity, dict):
            result.add_error(f"Entity {i} must be a dict", f"entities[{i}]")
            continue
        
        validate_entity_type(entity.get("type", ""), result)
        validate_entity_value(entity, result, i)
        validate_span_offsets(entity, text_length, result, i)
        validate_confidence_score(entity, result, i)
        validate_source_parser(entity, result, i)
    
    # Check for duplicates
    validate_deduplication(entities, result)
    
    # Check for overlapping spans
    validate_overlap(entities, result)
    
    return result


def validate_counts(output: Dict) -> ValidationResult:
    """
    Validate consistency between entities and counts.
    
    Checks:
    - total matches sum of per-type counts
    - per-type counts match entity counts
    """
    result = ValidationResult(valid=True)
    
    entities = output.get("entities", [])
    
    # Count entities by type
    type_counts: Dict[str, int] = {}
    for entity in entities:
        etype = entity.get("type", "UNKNOWN")
        type_counts[etype] = type_counts.get(etype, 0) + 1
    
    # Check if counts field exists and matches
    if "counts" in output:
        counts = output["counts"]
        if not isinstance(counts, dict):
            result.add_error("'counts' must be a dict", "counts")
        else:
            for etype, count in counts.items():
                actual = type_counts.get(etype, 0)
                if count != actual:
                    result.add_warning(
                        f"Count mismatch for {etype}: expected {actual}, got {count}",
                        f"counts[{etype}]"
                    )
    
    # Check total if present
    if "total" in output:
        total = output["total"]
        if total != len(entities):
            result.add_warning(
                f"Total mismatch: expected {len(entities)}, got {total}",
                "total"
            )
    
    return result


def validate_output(
    output: Dict,
    strict: bool = False,
    check_counts: bool = True,
) -> ValidationResult:
    """
    Main validation entry point.
    
    Args:
        output: Pipeline output dictionary
        strict: If True, treat warnings as errors
        check_counts: If True, validate entity counts
    
    Returns:
        ValidationResult with errors and warnings
    """
    # Run schema validation
    schema_result = validate_output_schema(output)
    
    # Run count validation if requested
    if check_counts:
        count_result = validate_counts(output)
        schema_result.merge(count_result)
    
    # Convert warnings to errors if strict mode
    if strict:
        for warning in schema_result.warnings:
            schema_result.add_error(
                warning.message,
                warning.field,
                warning.value
            )
        schema_result.warnings = []
    
    return schema_result


def format_validation_errors(result: ValidationResult) -> str:
    """Format validation errors for display."""
    lines = []
    
    if result.errors:
        lines.append("VALIDATION ERRORS:")
        for error in result.errors:
            lines.append(f"  - {error}")
    
    if result.warnings:
        lines.append("VALIDATION WARNINGS:")
        for warning in result.warnings:
            lines.append(f"  - {warning}")
    
    if not result.errors and not result.warnings:
        lines.append("Validation passed ✓")
    
    return "\n".join(lines)