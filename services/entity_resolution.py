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
from services.entities import PIIMatch
from services.engines.base_engine import EngineResult

logger = logging.getLogger(__name__)

# Engine trust weights (higher = more trusted as a source)
ENGINE_WEIGHTS: dict[str, float] = {
    "regex":  1.00,   # deterministic — highest trust
    "gliner": 0.85,   # GLiNER semantic NER — English
    "qwen_ner": 0.78, # Qwen 0.5B — multilingual + medical
    "llm":    0.78,   # Qwen 0.5B — multilingual + medical
    # otter and presidio removed
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
    "name", "father_name", "address", "organization", "city", "occupation",
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


def resolve(
    engine_results: list[EngineResult],
    source_text: str = "",
) -> list[ResolvedEntity]:
    """
    Merge and deduplicate all engine outputs into a canonical entity list.

    Steps:
      1. Collect all PIIMatch objects from every engine result.
      2. Span-ground check — discard entities whose value cannot be found in
         source_text. This is the grounding validator: it prevents hallucinated
         entities (values invented by generative models or OCR misreads that
         don't appear anywhere in the actual document text) from leaking into
         compliance output.
      3. Group by pii_type.
      4. Within each type: span-merge, deduplicate by value, fuse confidence.
      5. Sort by sensitivity (Critical → Low) then fused confidence.

    Args:
        engine_results: Outputs from all detection engines.
        source_text:    Normalised document text (used for grounding check).
                        If empty, grounding is skipped (backward compat).
    """
    all_matches: list[PIIMatch] = []
    for er in engine_results:
        all_matches.extend(er.matches)

    if not all_matches:
        return []

    # ── Span grounding check ──────────────────────────────────────────────────
    # Every entity value must be a substring of the source document text.
    # Discard any match whose value cannot be found — these are hallucinations,
    # OCR reconstruction errors, or model training-data leakage.
    # Regex matches already have confirmed spans so we skip them (fast path).
    # Numeric IDs are compared digit-only to handle space/dash formatting.
    if source_text:
        src_lower        = source_text.lower()
        src_digits       = re.sub(r"\D", "", source_text)
        # Whitespace-normalized version for OCR-fragmented text matching
        src_norm_ws      = re.sub(r"\s+", " ", source_text).lower()
        grounded: list[PIIMatch] = []
        skipped = 0
        for m in all_matches:
            if m.source == "regex":
                grounded.append(m)   # regex spans are always grounded
                continue
            v = m.value.strip()
            v_lower = v.lower()
            # Standard substring check
            if v_lower in src_lower:
                grounded.append(m)
                continue
            # Whitespace-normalized check: "Bhanderi Ankit" matches "Bhanderi\nAnkit"
            v_norm_ws = re.sub(r"\s+", " ", v_lower)
            if v_norm_ws in src_norm_ws:
                grounded.append(m)
                continue
            # Digit-only check for numeric IDs that may have spacing differences
            v_digits = re.sub(r"\D", "", v)
            if len(v_digits) >= 6 and v_digits in src_digits:
                grounded.append(m)
                continue
            # Token-presence check for multi-word names on OCR-fragmented ID cards.
            # If ALL tokens of a name appear (in order) in the normalized source, accept it.
            # This catches "Bhanderi Ankit Narsinhbhai" where each word is on its own line.
            words = v_lower.split()
            if len(words) >= 2:
                pattern = r"\s+".join(re.escape(w) for w in words)
                if re.search(pattern, src_lower):
                    grounded.append(m)
                    continue
            # Not found anywhere — discard
            logger.debug("[GROUNDING] DROP %s %r — not in source text", m.pii_type, v[:40])
            skipped += 1
        if skipped:
            logger.info("[GROUNDING] Discarded %d ungrounded entities", skipped)
        all_matches = grounded

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

        # Step A2: Phone subset suppression — drop local numbers that are
        # digit-tails of a longer international number already in the list
        if pii_type == "phone":
            merged = _suppress_phone_subsets(merged)

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
            _assert_semantic_span_integrity(best_match, source_text)

            # Build audit metadata for compliance traceability
            audit_metadata = {
                "engine_count": len(sources),
                "grounded": True,  # passed span grounding check above
                "filters_applied": [],
                "matched_by": sources,
            }
            # Record which engine provided the primary match
            if best_match.source == "regex":
                audit_metadata["matched_pattern"] = best_match.metadata.get("pattern", "regex")
            elif best_match.source in ("gliner", "qwen_ner"):
                audit_metadata["model_label"] = best_match.metadata.get("label", "")

            resolved.append(ResolvedEntity(
                pii_type=pii_type,
                value=canonical_value,
                confidence=fused_conf,
                sources=sources,
                start=best_match.start,
                end=best_match.end,
                context=best_match.context,
                sensitivity=sensitivity,
                metadata=audit_metadata,
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


def _assert_semantic_span_integrity(match: PIIMatch, source_text: str) -> None:
    """Semantic engines must not emit spans that point at different text."""
    if not source_text or match.source == "regex":
        return
    if match.start < 0 or match.end < 0:
        return
    if match.end > len(source_text) or match.start > match.end:
        raise AssertionError(
            f"semantic span outside normalized text for {match.pii_type}: "
            f"{match.start}:{match.end}"
        )
    span_text = source_text[match.start:match.end]
    span_norm = _span_norm(span_text)
    value_norm = _span_norm(match.value)
    assert value_norm in span_norm or span_norm in value_norm, (
        f"semantic span/value mismatch for {match.pii_type}: "
        f"{match.start}:{match.end}"
    )


def _span_norm(text: str) -> str:
    return re.sub(r"[\W_]+", "", text or "", flags=re.UNICODE).casefold()


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


def _suppress_phone_subsets(matches: list[PIIMatch]) -> list[PIIMatch]:
    """
    Suppress phone numbers that are digit-only subsets of a longer phone.

    +91 98765 43210  → digits: 919876543210  (keep)
       98765 43210   → digits:   9876543210  (suppress — tail of above)

    Rule: if digits(A) ends with digits(B) and len(digits(A)) > len(digits(B)),
    suppress B.
    """
    digit_vals = [(re.sub(r"\D", "", m.value), m) for m in matches]
    kept: list[PIIMatch] = []
    for i, (dv_i, m_i) in enumerate(digit_vals):
        is_subset = any(
            dv_j != dv_i and dv_j.endswith(dv_i) and len(dv_j) > len(dv_i)
            for dv_j, _ in digit_vals
            if dv_j != dv_i
        )
        if not is_subset:
            kept.append(m_i)
    return kept


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
    - For name/father_name, clean OCR noise (strip embedded lines, ID keywords).
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

    # Clean OCR name artifacts: take only first line and strip trailing noise
    if pii_type in {"name", "father_name"}:
        value = _clean_ocr_name(value)

    return value


# OCR keywords that appear in the middle/tail of misread names on Indian ID cards
_ID_NOISE_TOKENS = re.compile(
    r"(?i)\b(EPIC|VOTER|CARD|PAN|DOB|MALE|FEMALE|GOI|INDIA|ELECTION|"
    r"COMMISSION|COMMISSIONER|\d{4,}|[A-Z]{3,}\d{4,})\b"
)


def _clean_ocr_name(value: str) -> str:
    """
    Remove OCR artifacts from a name value:
    - Take only the first meaningful line (OCR concatenates adjacent card fields)
    - Strip trailing noise tokens (EPIC, DOB, card labels)
    - Collapse multiple spaces
    """
    if not value:
        return value

    # Take only the first line if there are embedded newlines
    lines = [ln.strip() for ln in re.split(r"[\n\r]+", value) if ln.strip()]
    if not lines:
        return value

    # Use the first line; if it's very short (< 3 chars) fall back to joining first 2
    first_line = lines[0]
    if len(first_line) < 3 and len(lines) > 1:
        first_line = " ".join(lines[:2])

    # Strip trailing noise tokens (OCR card field labels)
    cleaned = _ID_NOISE_TOKENS.sub("", first_line).strip()

    # Collapse multiple spaces
    cleaned = re.sub(r"\s{2,}", " ", cleaned).strip()

    # Fall back to original if cleaning emptied the value
    return cleaned if len(cleaned) >= 2 else first_line


# ── E. Confidence Fusion (simplified) ─────────────────────────────────────────

# Regex-primary types: regex confidence dominates completely
_REGEX_PRIMARY_TYPES: set[str] = {
    "aadhaar", "pan", "passport", "voter_id", "driving_license", "ssn",
    "phone", "email", "ifsc", "bank_account", "upi", "credit_card",
    "mrn", "abha_number", "ip_address", "pincode", "cvv", "expiry",
    "blood_group", "insurance_policy", "insurance_account_number",
    "employee_id", "user_id", "password", "nhs_number", "iban",
}


def _fuse_confidence(group: list[PIIMatch]) -> float:
    """
    Combine confidence scores from multiple engines.

    Simplified rules:
      - Regex-primary types: regex confidence dominates completely
      - Semantic types: max(engine_confidences) — simple and explainable
      - Multi-engine corroboration: +0.05 per extra engine (capped at 1.0)
    """
    if not group:
        return 0.0

    # Determine if this is a regex-primary type
    pii_type = group[0].pii_type if group else ""

    if pii_type in _REGEX_PRIMARY_TYPES:
        # Regex dominates completely for structured ID types
        regex_matches = [m for m in group if m.source == "regex"]
        if regex_matches:
            return min(round(regex_matches[0].confidence, 4), 1.0)

    # Semantic types: use max confidence across engines
    max_conf = max(m.confidence for m in group)

    # Multi-engine corroboration bonus
    unique_engines = {m.source for m in group}
    bonus = 0.05 * (len(unique_engines) - 1)

    return min(round(max_conf + bonus, 4), 1.0)


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
