"""
services/validator.py
-----------------------
Validation Layer — quality assurance after entity resolution.

Validates:
  • Missed entities     — known PII patterns not caught by any engine
  • Overlap conflicts   — two entities with the same span, different types
  • False positives     — high-confidence hits that fail a secondary check
  • Span correctness    — entity value actually appears in the source text
  • Redaction coverage  — every resolved entity has a redaction entry
  • Ground truth eval   — optional precision / recall / F1 vs a labelled set

Returns a ValidationReport appended to the final JSON output.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import Optional

from constants import PII_TYPE_MAP, SENSITIVITY_ORDER

logger = logging.getLogger(__name__)


# ── Result types ──────────────────────────────────────────────────────────────

@dataclass
class ValidationIssue:
    severity:    str    # "error" | "warning" | "info"
    code:        str    # short machine-readable code
    message:     str
    pii_type:    str  = ""
    value:       str  = ""
    span_start:  int  = -1
    span_end:    int  = -1


@dataclass
class GroundTruthMetrics:
    """Precision / Recall / F1 against a labelled ground truth set."""
    true_positives:  int   = 0
    false_positives: int   = 0
    false_negatives: int   = 0
    precision:       float = 0.0
    recall:          float = 0.0
    f1:              float = 0.0
    span_accuracy:   float = 0.0   # fraction of TP with correct span


@dataclass
class ValidationReport:
    """Complete validation output appended to every scan result."""
    issues:          list[ValidationIssue]  = field(default_factory=list)
    overlap_count:   int                    = 0
    fp_count:        int                    = 0
    missed_count:    int                    = 0
    span_errors:     int                    = 0
    coverage:        float                  = 1.0   # redaction coverage ratio
    ground_truth:    Optional[GroundTruthMetrics] = None
    passed:          bool                   = True

    def summary(self) -> dict:
        return {
            "passed":        self.passed,
            "issues":        len(self.issues),
            "overlap_conflicts": self.overlap_count,
            "false_positives":   self.fp_count,
            "missed_entities":   self.missed_count,
            "span_errors":       self.span_errors,
            "redaction_coverage": round(self.coverage, 4),
            "issue_details": [
                {
                    "severity": i.severity,
                    "code":     i.code,
                    "message":  i.message,
                    "pii_type": i.pii_type,
                    "value":    i.value,
                }
                for i in self.issues
            ],
        }


# ── Validator ─────────────────────────────────────────────────────────────────

class Validator:

    def validate(
        self,
        text: str,
        resolved_entities: list,          # list[ResolvedEntity]
        redactions: Optional[list] = None,
        ground_truth: Optional[list[dict]] = None,
    ) -> ValidationReport:
        """
        Run all validation checks and return a ValidationReport.

        Args:
            text:              Original (pre-normalisation) document text.
            resolved_entities: Output of entity_resolution.resolve().
            redactions:        Optional list of redaction records for coverage check.
            ground_truth:      Optional list of {pii_type, value} dicts for F1 eval.
        """
        report = ValidationReport()
        issues: list[ValidationIssue] = []

        # 1. Span correctness
        span_errors = self._check_span_correctness(text, resolved_entities, issues)
        report.span_errors = span_errors

        # 2. Overlap conflicts
        overlaps = self._check_overlaps(resolved_entities, issues)
        report.overlap_count = overlaps

        # 3. False positive quick-check
        fps = self._check_false_positives(resolved_entities, issues)
        report.fp_count = fps

        # 4. Missed entities (quick re-scan with high-confidence patterns)
        missed = self._check_missed_entities(text, resolved_entities, issues)
        report.missed_count = missed

        # 5. Redaction coverage
        if redactions is not None:
            coverage = self._check_redaction_coverage(resolved_entities, redactions, issues)
            report.coverage = coverage

        # 6. Ground truth evaluation
        if ground_truth:
            report.ground_truth = self._evaluate_ground_truth(
                resolved_entities, ground_truth
            )

        report.issues = issues
        report.passed = not any(i.severity == "error" for i in issues)

        logger.info(
            "[VALIDATOR] passed=%s issues=%d overlaps=%d fps=%d missed=%d span_errors=%d",
            report.passed, len(issues), overlaps, fps, missed, span_errors,
        )
        return report

    # ── Check: Span Correctness ───────────────────────────────────────────────

    def _check_span_correctness(
        self, text: str, entities: list, issues: list[ValidationIssue]
    ) -> int:
        """Verify each entity's value actually appears at its reported span."""
        errors = 0
        for e in entities:
            if e.start < 0 or e.end < 0:
                continue   # span unknown — skip
            actual = text[e.start:e.end]
            # Strip whitespace for comparison
            if actual.strip().lower() != e.value.strip().lower():
                # Try a substring search as fallback
                found_pos = text.lower().find(e.value.lower())
                if found_pos == -1:
                    issues.append(ValidationIssue(
                        severity="warning",
                        code="SPAN_VALUE_MISMATCH",
                        message=f"Entity value {e.value!r} not found at span [{e.start}:{e.end}]",
                        pii_type=e.pii_type,
                        value=e.value,
                        span_start=e.start,
                        span_end=e.end,
                    ))
                    errors += 1
        return errors

    # ── Check: Overlaps ───────────────────────────────────────────────────────

    def _check_overlaps(self, entities: list, issues: list[ValidationIssue]) -> int:
        """Detect two entities with conflicting overlapping spans."""
        conflicts = 0
        with_spans = [e for e in entities if e.start >= 0 and e.end >= 0]
        for i, a in enumerate(with_spans):
            for b in with_spans[i + 1:]:
                if a.pii_type == b.pii_type:
                    continue   # same type overlap is handled by resolution
                # Check overlap
                if not (a.end <= b.start or b.end <= a.start):
                    issues.append(ValidationIssue(
                        severity="warning",
                        code="SPAN_OVERLAP_CONFLICT",
                        message=(
                            f"[{a.pii_type}] {a.value!r} overlaps with "
                            f"[{b.pii_type}] {b.value!r} at spans "
                            f"[{a.start}:{a.end}] vs [{b.start}:{b.end}]"
                        ),
                        pii_type=f"{a.pii_type}+{b.pii_type}",
                        value=f"{a.value} / {b.value}",
                        span_start=min(a.start, b.start),
                        span_end=max(a.end, b.end),
                    ))
                    conflicts += 1
        return conflicts

    # ── Check: False Positives ────────────────────────────────────────────────

    def _check_false_positives(
        self, entities: list, issues: list[ValidationIssue]
    ) -> int:
        """Quick secondary checks to flag likely false positives."""
        fps = 0
        for e in entities:
            flagged = False

            if e.pii_type == "aadhaar":
                # Aadhaar must be 12 digits
                digits = re.sub(r"\D", "", e.value)
                if len(digits) != 12:
                    flagged = True
                    issues.append(ValidationIssue(
                        severity="warning", code="FP_AADHAAR_DIGIT_COUNT",
                        message=f"Aadhaar {e.value!r} has {len(digits)} digits, expected 12",
                        pii_type="aadhaar", value=e.value,
                    ))

            elif e.pii_type == "pan":
                if not re.fullmatch(r"[A-Z]{5}[0-9]{4}[A-Z]", e.value.upper()):
                    flagged = True
                    issues.append(ValidationIssue(
                        severity="warning", code="FP_PAN_FORMAT",
                        message=f"PAN {e.value!r} does not match AAAAA9999A format",
                        pii_type="pan", value=e.value,
                    ))

            elif e.pii_type == "email":
                if not re.fullmatch(
                    r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}", e.value
                ):
                    flagged = True
                    issues.append(ValidationIssue(
                        severity="info", code="FP_EMAIL_FORMAT",
                        message=f"Email {e.value!r} may be malformed",
                        pii_type="email", value=e.value,
                    ))

            elif e.pii_type == "credit_card":
                # Re-run Luhn check
                digits = re.sub(r"\D", "", e.value)
                if not _luhn_valid(digits):
                    flagged = True
                    issues.append(ValidationIssue(
                        severity="warning", code="FP_CC_LUHN_FAIL",
                        message=f"Credit card {e.value!r} fails Luhn check",
                        pii_type="credit_card", value=e.value,
                    ))

            elif e.pii_type == "name":
                # Single-token names are suspicious
                tokens = e.value.strip().split()
                if len(tokens) < 2:
                    issues.append(ValidationIssue(
                        severity="info", code="LOW_CONF_SINGLE_TOKEN_NAME",
                        message=f"Name {e.value!r} is single-token — low confidence",
                        pii_type="name", value=e.value,
                    ))

            if flagged:
                fps += 1
        return fps

    # ── Check: Missed Entities ────────────────────────────────────────────────

    def _check_missed_entities(
        self, text: str, entities: list, issues: list[ValidationIssue]
    ) -> int:
        """
        Quick re-scan with high-precision patterns for the most critical
        PII types to catch anything the full pipeline may have missed.
        """
        found_values = {e.value.lower() for e in entities}
        missed = 0

        # Critical patterns only — we want high precision here
        _CRITICAL_CHECKS: list[tuple[str, re.Pattern]] = [
            ("aadhaar",     re.compile(r"(?<!\d)\d{4}\s\d{4}\s\d{4}(?!\d)")),
            ("pan",         re.compile(r"\b[A-Z]{5}[0-9]{4}[A-Z]\b")),
            ("email",       re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")),
            ("phone",       re.compile(r"(?<!\d)(?:\+91[\s\-]?)?[6-9]\d{9}(?!\d)")),
            ("credit_card", re.compile(r"\b(?:\d[ -]*?){16}\b")),
        ]

        for pii_type, pattern in _CRITICAL_CHECKS:
            for m in pattern.finditer(text):
                val = m.group().strip().lower()
                if val not in found_values:
                    # Only flag if the entity type is completely absent
                    existing_types = {e.pii_type for e in entities}
                    if pii_type not in existing_types:
                        issues.append(ValidationIssue(
                            severity="warning",
                            code="POSSIBLE_MISSED_ENTITY",
                            message=f"Possible {pii_type} not in resolved entities: {m.group()!r}",
                            pii_type=pii_type,
                            value=m.group().strip(),
                            span_start=m.start(),
                            span_end=m.end(),
                        ))
                        missed += 1

        return missed

    # ── Check: Redaction Coverage ─────────────────────────────────────────────

    def _check_redaction_coverage(
        self, entities: list, redactions: list, issues: list[ValidationIssue]
    ) -> float:
        """
        Ensure every resolved entity above LOW sensitivity has a redaction entry.
        Returns coverage ratio (0.0–1.0).
        """
        from constants import Sensitivity

        critical_entities = [
            e for e in entities
            if SENSITIVITY_ORDER.get(e.sensitivity, 0) >= SENSITIVITY_ORDER[Sensitivity.MEDIUM]
        ]
        if not critical_entities:
            return 1.0

        redacted_values = {r.get("value", "").lower() for r in redactions}
        unredacted = [
            e for e in critical_entities
            if e.value.lower() not in redacted_values
        ]

        for e in unredacted:
            issues.append(ValidationIssue(
                severity="warning",
                code="UNREDACTED_SENSITIVE_ENTITY",
                message=f"Sensitive [{e.pii_type}] {e.value!r} has no redaction entry",
                pii_type=e.pii_type,
                value=e.value,
            ))

        covered = len(critical_entities) - len(unredacted)
        return covered / len(critical_entities) if critical_entities else 1.0

    # ── Ground Truth Evaluation ───────────────────────────────────────────────

    def _evaluate_ground_truth(
        self,
        entities: list,
        ground_truth: list[dict],
    ) -> GroundTruthMetrics:
        """
        Compute precision / recall / F1 against a labelled ground truth set.

        Ground truth format: [{"pii_type": "aadhaar", "value": "1234..."}, ...]
        """
        gt_set  = {(g["pii_type"], g["value"].lower()) for g in ground_truth}
        pred_set = {(e.pii_type, e.value.lower()) for e in entities}

        tp = len(gt_set & pred_set)
        fp = len(pred_set - gt_set)
        fn = len(gt_set - pred_set)

        precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        recall    = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        f1        = (2 * precision * recall / (precision + recall)
                     if (precision + recall) > 0 else 0.0)

        logger.info(
            "[VALIDATOR] Ground truth — P=%.3f R=%.3f F1=%.3f (TP=%d FP=%d FN=%d)",
            precision, recall, f1, tp, fp, fn,
        )
        return GroundTruthMetrics(
            true_positives=tp,
            false_positives=fp,
            false_negatives=fn,
            precision=round(precision, 4),
            recall=round(recall, 4),
            f1=round(f1, 4),
        )


# ── Helpers ───────────────────────────────────────────────────────────────────

def _luhn_valid(digits: str) -> bool:
    if not digits.isdigit() or len(digits) < 13:
        return False
    total = 0
    for i, ch in enumerate(reversed(digits)):
        d = int(ch)
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


# ── Module-level singleton ────────────────────────────────────────────────────

_validator = Validator()


def validate_results(
    text: str,
    resolved_entities: list,
    redactions: Optional[list] = None,
    ground_truth: Optional[list[dict]] = None,
) -> ValidationReport:
    return _validator.validate(text, resolved_entities, redactions, ground_truth)
