"""
services/entity_resolution.py
--------------------------------
Entity Resolution Layer — the convergence point of ALL detection engines.

Responsibilities:
  A. Span Merging      — collapse nested/partial matches ("John" ⊂ "John Doe")
  B. Type Resolution   — disambiguate ambiguous entities (12-digit number: Aadhaar vs account?)
  C. Duplicate Elimination — deduplicate by normalised value within same PII type
  D. Canonicalization  — normalize value representation (strip extra spaces, etc.)
  E. Confidence Fusion — combine scores from multiple engines for the same entity

Input:  list of EngineResult (one per engine that ran)
Output: list of PIIMatch — deduplicated, merged, scored, canonical
"""

from __future__ import annotations

import logging
import re
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Optional

from constants import PII_TYPE_MAP, SENSITIVITY_ORDER
from services.engines.base_engine import EngineResult, PIIMatch

logger = logging.getLogger(__name__)

# Engine trust weights (higher = more trusted as a source)
ENGINE_WEIGHTS: dict[str, float] = {
    "regex":   1.0,   # deterministic — highest trust
    "otter":   0.85,  # structural + key-value
    "gliner":  0.80,  # semantic NER
    "llm":     0.75,  # semantic reasoning
    "presidio": 0.80, # legacy Presidio NER
}

# For these types, prefer exact-match dedup (normalise digits only)
_NUMERIC_DEDUPE_TYPES: set[str] = {
    "aadhaar", "credit_card", "bank_account", "phone", "ssn",
}

# Alphanumeric IDs — dedup by normalising case but keep structure
_ALPHANUM_DEDUPE_TYPES: set[str] = {
    "pan", "passport", "voter_id", "driving_license",
    "upi", "ifsc", "insurance_policy", "mrn", "employee_id",
}

# For these types, prefer case-insensitive string dedup
_TEXT_DEDUPE_TYPES: set[str] = {
    "email", "ip_address", "user_id", "upi",
}

# For these semantic types, looser dedup (normalised whitespace only)
_SOFT_DEDUPE_TYPES: set[str] = {
    "name", "address", "organization", "city", "occupation",
    "diagnosis", "allergies", "treatment_history", "prescription",
    "educational_qualification", "insurance_provider", "nationality",
}


@dataclass
class ResolvedEntity:
    """Final canonical PII entity after resolution."""
    pii_type:    str
    value:       str           # canonical normalised value
    confidence:  float         # fused confidence (0.0–1.0)
    sources:     list[str]     # which engines contributed
    start:       int = -1      # span in original text (-1 = unknown)
    end:         int = -1
    context:     str = ""
    sensitivity: str = ""      # from PII_TYPE_MAP
    metadata:    dict = field(default_factory=dict)


def resolve(engine_results: list[EngineResult]) -> list[ResolvedEntity]:
    """
    Merge and deduplicate all engine outputs into a canonical entity list.

    Steps:
      1. Collect all PIIMatch objects from every engine result.
      2. Group by pii_type.
      3. Within each type: span-merge, deduplicate by value, fuse confidence.
      4. Sort by sensitivity (Critical → Low) then fused confidence.
    """
    all_matches: list[PIIMatch] = []
    for er in engine_results:
        all_matches.extend(er.matches)

    if not all_matches:
        return []

    # Group by pii_type
    by_type: dict[str, list[PIIMatch]] = defaultdict(list)
    for m in all_matches:
        by_type[m.pii_type].append(m)

    resolved: list[ResolvedEntity] = []

    for pii_type, matches in by_type.items():
        type_info = PII_TYPE_MAP.get(pii_type)
        sensitivity = type_info["sensitivity"] if type_info else "Low"

        # Step A+B: Span merge — collapse contained spans of the same type
        merged = _merge_spans(matches)

        # Step C: Deduplicate by normalised value
        deduped = _deduplicate(merged, pii_type)

        # Step D+E: Canonicalize + fuse confidence
        for group in deduped:
            canonical_value = _canonicalize(group, pii_type)
            fused_conf = _fuse_confidence(group)
            sources = sorted({m.source for m in group})

            # Pick best span (prefer regex > otter > gliner > llm)
            best_match = sorted(
                group,
                key=lambda m: ENGINE_WEIGHTS.get(m.source, 0.5),
                reverse=True,
            )[0]

            resolved.append(ResolvedEntity(
                pii_type=pii_type,
                value=canonical_value,
                confidence=fused_conf,
                sources=sources,
                start=best_match.start,
                end=best_match.end,
                context=best_match.context,
                sensitivity=sensitivity,
                metadata={"engine_count": len(sources)},
            ))

    # Sort: sensitivity desc, then confidence desc
    resolved.sort(
        key=lambda e: (
            -SENSITIVITY_ORDER.get(e.sensitivity, 1),
            -e.confidence,
        )
    )

    logger.info(
        "[RESOLUTION] %d raw matches → %d resolved entities",
        len(all_matches), len(resolved),
    )
    return resolved


# ── A. Span Merging ───────────────────────────────────────────────────────────

def _merge_spans(matches: list[PIIMatch]) -> list[PIIMatch]:
    """
    When two matches of the same type overlap, keep the longer/higher-
    confidence one and discard the contained one.

    e.g. "John" (regex) ⊂ "John Doe" (gliner) → keep "John Doe"
    """
    if len(matches) <= 1:
        return matches

    # Separate known-span vs span-unknown matches
    with_span    = [m for m in matches if m.start >= 0 and m.end >= 0]
    without_span = [m for m in matches if m.start < 0 or m.end < 0]

    # Sort by start, then by length desc (longer first)
    with_span.sort(key=lambda m: (m.start, -(m.end - m.start)))

    kept: list[PIIMatch] = []
    for m in with_span:
        dominated = any(
            k.start <= m.start and k.end >= m.end
            for k in kept
        )
        if not dominated:
            # If this match dominates an already-kept one, replace it
            kept = [
                k for k in kept
                if not (m.start <= k.start and m.end >= k.end)
            ]
            kept.append(m)

    return kept + without_span


# ── C. Deduplication ─────────────────────────────────────────────────────────

def _normalise_key(value: str, pii_type: str) -> str:
    """Return a normalised key for deduplication comparison."""
    if pii_type in _NUMERIC_DEDUPE_TYPES:
        return re.sub(r"\D", "", value)
    if pii_type in _ALPHANUM_DEDUPE_TYPES:
        return re.sub(r"[\s\-/]", "", value).upper()
    if pii_type in _TEXT_DEDUPE_TYPES:
        return value.strip().lower()
    # Soft dedup: collapse whitespace, lowercase
    return re.sub(r"\s+", " ", value).strip().lower()


def _deduplicate(matches: list[PIIMatch], pii_type: str) -> list[list[PIIMatch]]:
    """
    Group matches by normalised value key.
    Returns list-of-groups; each group represents the same logical entity.
    """
    groups: dict[str, list[PIIMatch]] = {}
    for m in matches:
        key = _normalise_key(m.value, pii_type)
        if not key:
            key = m.value[:50]
        if key not in groups:
            groups[key] = []
        groups[key].append(m)
    return list(groups.values())


# ── D. Canonicalization ───────────────────────────────────────────────────────

def _canonicalize(group: list[PIIMatch], pii_type: str) -> str:
    """
    Pick the most representative value from a group of matches.
    - Prefer the longest non-empty value (more complete).
    - For numeric types, strip non-digits.
    """
    # Prefer regex matches (most precise)
    regex_hits = [m for m in group if m.source == "regex"]
    if regex_hits:
        best = max(regex_hits, key=lambda m: len(m.value))
    else:
        best = max(group, key=lambda m: len(m.value))

    value = best.value.strip()

    if pii_type in _NUMERIC_DEDUPE_TYPES:
        digits = re.sub(r"\D", "", value)
        if digits:
            return digits

    return value


# ── E. Confidence Fusion ──────────────────────────────────────────────────────

def _fuse_confidence(group: list[PIIMatch]) -> float:
    """
    Combine confidence scores from multiple engines.

    Rule: weighted average of engine scores, capped at 1.0.
    Multi-engine corroboration lifts score: each extra engine adds +0.05.
    """
    if not group:
        return 0.0

    weighted_sum = sum(
        m.confidence * ENGINE_WEIGHTS.get(m.source, 0.5)
        for m in group
    )
    weight_total = sum(ENGINE_WEIGHTS.get(m.source, 0.5) for m in group)
    base = weighted_sum / weight_total if weight_total > 0 else 0.0

    # Corroboration bonus
    unique_engines = {m.source for m in group}
    bonus = 0.05 * (len(unique_engines) - 1)

    return min(round(base + bonus, 4), 1.0)


# ── Public helpers ────────────────────────────────────────────────────────────

def resolved_to_pii_counts(resolved: list[ResolvedEntity]) -> dict[str, int]:
    """Convert resolved entities to {pii_type: count} — used by scan logic."""
    counts: dict[str, int] = defaultdict(int)
    for e in resolved:
        counts[e.pii_type] += 1
    return dict(counts)


def select_primary_from_resolved(
    resolved: list[ResolvedEntity],
    allowed_types: Optional[set[str]] = None,
) -> tuple[str | None, int, float]:
    """
    Pick the primary PII type from resolved entities.
    Returns (pii_type, count, score) — replaces legacy select_primary_pii.
    """
    from constants import SENSITIVITY_ORDER

    filtered = [
        e for e in resolved
        if not allowed_types or e.pii_type in allowed_types
    ]

    if not filtered:
        return None, 0, 0.0

    # Group by type
    by_type: dict[str, list[ResolvedEntity]] = defaultdict(list)
    for e in filtered:
        by_type[e.pii_type].append(e)

    best_type: str | None = None
    best_count = 0
    best_score = -1.0

    for pii_type, entities in by_type.items():
        count    = len(entities)
        avg_conf = sum(e.confidence for e in entities) / count
        priority = SENSITIVITY_ORDER.get(entities[0].sensitivity, 1)
        score    = priority * avg_conf * count

        if score > best_score:
            best_type  = pii_type
            best_count = count
            best_score = score

    return best_type, best_count, best_score
