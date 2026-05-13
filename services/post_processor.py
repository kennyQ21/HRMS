"""
services/post_processor.py
---------------------------
Post-processing layer applied to resolved entities BEFORE the final response.

Simplified architecture:
  1. Confidence gate      — drop entities below per-type minimum
  2. Length gate          — reject multi-sentence / word-soup entities
  3. Stopword rejection   — reject role words / pronouns detected as names
  4. Section-header filter— reject document structure labels as entities
  5. Drug canonicalization— normalize known drug names to `medication` type
  6. Diagnosis filter     — reject non-clinical sentences labelled as diagnosis
  7. Placeholder rejection— reject LLM "none found" / "not provided" outputs

Removed (unstable across OCR/Indic/Arabic/multilingual):
  - Colon suffix heuristics
  - Organization >8 words style heuristics
  - Complex sentence morphology checks
  - Weird capitalization heuristics
  - Leading "The" stripping
  - Generic insurance/prescription keyword filters
"""
from __future__ import annotations

import logging
import re
from typing import List

logger = logging.getLogger(__name__)

# ── 1. Per-type minimum confidence ───────────────────────────────────────────

_MIN_CONFIDENCE: dict[str, float] = {
    "name":                    0.20,
    "father_name":             0.20,
    "organization":            0.40,
    "diagnosis":               0.75,
    "address":                 0.20,
    "allergies":               0.65,
    "treatment_history":       0.70,
}
_DEFAULT_MIN_CONF = 0.50

# ── 2. Max word count per type ────────────────────────────────────────────────

_MAX_WORDS: dict[str, int] = {
    "name":                    6,
    "father_name":             5,
    "organization":            8,
    "diagnosis":               12,
    "allergies":               8,
    "treatment_history":       20,
    "address":                 25,
}
_DEFAULT_MAX_WORDS = 30

# ── 3. Stopwords that must never be entities ──────────────────────────────────

_NAME_STOPWORDS: frozenset[str] = frozenset({
    # Affirmations / filler
    "yes", "no", "sure", "okay", "ok", "thank", "thanks", "please",
    "hello", "hi", "hey", "yeah", "yep", "nope", "right", "correct",
    "exactly", "absolutely", "definitely", "certainly", "well",
    # Pronouns
    "i", "me", "my", "myself", "we", "our", "us", "you", "your",
    "yourself", "they", "them", "their", "it", "its", "he", "she",
    "him", "her", "this", "that", "these", "those",
    # Role / occupational (NOT names)
    "patient", "patients", "client", "clients", "customer", "customers",
    "respondent", "respondents", "individual", "individuals",
    "person", "people", "member", "members", "user", "users",
    "employee", "employees", "staff", "worker", "workers",
    "interviewer", "interviewee", "speaker", "narrator", "host", "guest",
    "doctor", "nurse", "physician", "pharmacist", "provider", "prescriber",
    "caregiver", "practitioner", "specialist", "analyst", "consultant",
})

# ── 4. Known drug names → medication ─────────────────────────────────────────

_KNOWN_DRUGS: dict[str, str] = {
    # Biologics / immunology
    "humira": "Humira (adalimumab)",
    "adalimumab": "Humira (adalimumab)",
    "remicade": "Remicade (infliximab)",
    "infliximab": "Remicade (infliximab)",
    "enbrel": "Enbrel (etanercept)",
    "etanercept": "Enbrel (etanercept)",
    "dupixent": "Dupixent (dupilumab)",
    "dupilumab": "Dupixent (dupilumab)",
    "cosentyx": "Cosentyx (secukinumab)",
    "skyrizi": "Skyrizi (risankizumab)",
    "tremfya": "Tremfya (guselkumab)",
    "stelara": "Stelara (ustekinumab)",
    "otezla": "Otezla (apremilast)",
    "taltz": "Taltz (ixekizumab)",
    # Oncology
    "keytruda": "Keytruda (pembrolizumab)",
    "pembrolizumab": "Keytruda (pembrolizumab)",
    "opdivo": "Opdivo (nivolumab)",
    "nivolumab": "Opdivo (nivolumab)",
    "revlimid": "Revlimid (lenalidomide)",
    "lenalidomide": "Revlimid (lenalidomide)",
    "herceptin": "Herceptin (trastuzumab)",
    "trastuzumab": "Herceptin (trastuzumab)",
    "rituxan": "Rituxan (rituximab)",
    "rituximab": "Rituxan (rituximab)",
    # MS drugs
    "tecfidera": "Tecfidera (dimethyl fumarate)",
    "copaxone": "Copaxone (glatiramer)",
    "avonex": "Avonex (interferon beta-1a)",
    "betaseron": "Betaseron (interferon beta-1b)",
    "ocrevus": "Ocrevus (ocrelizumab)",
    "ocrelizumab": "Ocrevus (ocrelizumab)",
    "tysabri": "Tysabri (natalizumab)",
    "natalizumab": "Tysabri (natalizumab)",
    # Diabetes / metabolic
    "ozempic": "Ozempic (semaglutide)",
    "wegovy": "Wegovy (semaglutide)",
    "semaglutide": "Ozempic/Wegovy (semaglutide)",
    "jardiance": "Jardiance (empagliflozin)",
    "empagliflozin": "Jardiance (empagliflozin)",
    "januvia": "Januvia (sitagliptin)",
    "metformin": "Metformin",
    "insulin": "Insulin",
    "lantus": "Lantus (insulin glargine)",
    # Cardiovascular
    "eliquis": "Eliquis (apixaban)",
    "apixaban": "Eliquis (apixaban)",
    "xarelto": "Xarelto (rivaroxaban)",
    "rivaroxaban": "Xarelto (rivaroxaban)",
    "warfarin": "Warfarin",
    "coumadin": "Coumadin (warfarin)",
    "lipitor": "Lipitor (atorvastatin)",
    "atorvastatin": "Atorvastatin",
    "lisinopril": "Lisinopril",
    # Common generics
    "prednisone": "Prednisone",
    "methotrexate": "Methotrexate",
    "hydroxychloroquine": "Hydroxychloroquine",
    "plaquenil": "Plaquenil (hydroxychloroquine)",
    "amoxicillin": "Amoxicillin",
    "azithromycin": "Azithromycin",
    "levothyroxine": "Levothyroxine",
}

# ── 5. Section-header patterns to reject ─────────────────────────────────────

_SECTION_HEADER = re.compile(
    r"(?i)^(?:"
    r"[IVX]+\.\s|"                          # Roman numeral prefix: "V. ", "X. "
    r"(?:wrap[\s\-]?up|introduction|overview|summary|background|"
    r"conclusion|appendix|references|discussion|results|methodology|"
    r"objectives|strategy|roadmap|requirements|findings|analysis)\b|"
    r".*\binterview\s+transcript\b|"
    r".*\brespondent\s*:\s*|"
    r".*\binterviewer\s*:\s*"
    r")"
)

# ── 6. LLM placeholder / hallucination rejection ─────────────────────────────

_LLM_PLACEHOLDERS = re.compile(
    r"(?i)^(?:"
    r"none\s*(?:listed|provided|mentioned|available|found|given)?\.?"
    r"|not\s+(?:provided|mentioned|available|listed|applicable|found|specified)"
    r"|no\s+(?:specific\s+)?(?:information|data|detail|value|entry|result|entity|name|id)"
    r"|n/?a\.?|unknown|not\s+applicable|not\s+stated"
    r")$"
)

# Script / language names that LLM or GLiNER emit as entity values
_SCRIPT_LANGUAGE_NAMES: frozenset[str] = frozenset({
    "devanagari", "devanagari script", "latin", "arabic script",
    "bengali script", "tamil script", "telugu script", "kannada script",
    "malayalam script", "gujarati script", "gurmukhi script",
    "thai script", "chinese script", "cyrillic script",
    "hangul", "hiragana", "katakana",
    "english", "hindi", "arabic", "chinese", "japanese", "korean",
    "french", "german", "spanish", "portuguese", "russian", "urdu",
    "bengali", "tamil", "telugu", "kannada", "malayalam", "gujarati",
    "punjabi", "marathi", "odia", "konkani", "assamese",
    "thai", "vietnamese", "indonesian", "malay",
    "pii", "pii sample", "synthetic data", "fictitious", "sample document",
})

# ── 7. Diagnosis clinical indicator ───────────────────────────────────────────

_CLINICAL_INDICATORS = re.compile(
    r"(?i)\b(?:disease|disorder|syndrome|condition|infection|cancer|"
    r"carcinoma|lymphoma|leukemia|tumor|tumour|diabetes|hypertension|"
    r"hypotension|arthritis|sclerosis|lupus|psoriasis|colitis|anemia|"
    r"neuropathy|hepatitis|asthma|copd|eczema|melanoma|autoimmune|"
    r"chronic|acute|malignancy|benign|diagnosed|diagnosis|pathy|itis|"
    r"emia|osis|cardio|renal|hepatic|pulmonary|cardiac|neurologic)\b"
)

# ── Helpers ───────────────────────────────────────────────────────────────────

def _word_count(text: str) -> int:
    return len(text.split())


# Unicode blocks for non-Latin scripts
_NON_LATIN_RANGES = [
    (0x0900, 0x097F),  # Devanagari
    (0x0980, 0x09FF),  # Bengali
    (0x0A00, 0x0A7F),  # Gurmukhi
    (0x0A80, 0x0AFF),  # Gujarati
    (0x0B00, 0x0B7F),  # Odia
    (0x0B80, 0x0BFF),  # Tamil
    (0x0C00, 0x0C7F),  # Telugu
    (0x0C80, 0x0CFF),  # Kannada
    (0x0D00, 0x0D7F),  # Malayalam
    (0x0600, 0x06FF),  # Arabic
    (0x0590, 0x05FF),  # Hebrew
    (0x4E00, 0x9FFF),  # CJK
    (0x3040, 0x309F),  # Hiragana
    (0x30A0, 0x30FF),  # Katakana
    (0xAC00, 0xD7AF),  # Hangul
    (0x0400, 0x04FF),  # Cyrillic
    (0x0E00, 0x0E7F),  # Thai
]


def _is_non_latin(text: str) -> bool:
    """Check if text starts with a non-Latin script character."""
    if not text or not text.strip():
        return False
    first_char = text.strip()[0]
    cp = ord(first_char)
    for lo, hi in _NON_LATIN_RANGES:
        if lo <= cp <= hi:
            return True
    return False


def _starts_uppercase(text: str) -> bool:
    stripped = text.strip()
    if not stripped:
        return False
    if _is_non_latin(stripped):
        return True
    return stripped[0].isupper()


def _is_mostly_lowercase_sentence(text: str) -> bool:
    """True if the text looks like a prose sentence (not a proper entity)."""
    if _is_non_latin(text):
        return False
    words = text.split()
    if len(words) < 4:
        return False
    lowercase = sum(1 for w in words if w and w[0].islower())
    return lowercase / len(words) > 0.6


# ── Main entry point ──────────────────────────────────────────────────────────

def post_process(resolved: list) -> list:
    """
    Apply all post-processing rules to a list of ResolvedEntity objects.
    Returns a filtered, possibly modified list.
    """
    from services.entity_resolution import ResolvedEntity

    immutable_spans = {id(e): (e.value, e.start, e.end) for e in resolved}
    kept: list[ResolvedEntity] = []
    drug_entities: list[ResolvedEntity] = []

    for entity in resolved:
        ptype  = entity.pii_type
        value  = entity.value.strip()
        conf   = entity.confidence
        wcount = _word_count(value)
        vlower = value.lower()

        # ── 1. Confidence gate ────────────────────────────────────────────────
        min_conf = _MIN_CONFIDENCE.get(ptype, _DEFAULT_MIN_CONF)
        if conf < min_conf:
            logger.debug("[PP] DROP %s %r -- conf %.2f < %.2f", ptype, value[:40], conf, min_conf)
            continue

        # ── 1b. LLM placeholder rejection ────────────────────────────────────
        if "llm" in entity.sources:
            if _LLM_PLACEHOLDERS.match(value):
                logger.debug("[PP] DROP %s %r -- LLM placeholder", ptype, value[:40])
                continue
            if vlower in _SCRIPT_LANGUAGE_NAMES:
                logger.debug("[PP] DROP %s %r -- script/language name", ptype, value[:40])
                continue
            # Reject comma-separated mixed-type dumps
            if value.count(",") >= 2 and wcount > 3:
                logger.debug("[PP] DROP %s %r -- LLM data dump", ptype, value[:40])
                continue

        # ── 2. Length gate ────────────────────────────────────────────────────
        max_words = _MAX_WORDS.get(ptype, _DEFAULT_MAX_WORDS)
        if wcount > max_words:
            logger.debug("[PP] DROP %s %r -- %d words > %d", ptype, value[:40], wcount, max_words)
            continue

        # ── 3. Stopword rejection + type-specific guards ──────────────────────
        if ptype == "name":
            if vlower in _NAME_STOPWORDS:
                logger.debug("[PP] DROP name %r -- stopword", value)
                continue
            if wcount == 1 and value == value.lower():
                logger.debug("[PP] DROP name %r -- all lowercase single word", value)
                continue
            # Allow single capitalized words (e.g. "Pratik" is a valid Indian name)
            if _is_mostly_lowercase_sentence(value):
                logger.debug("[PP] DROP name %r -- looks like a sentence", value[:40])
                continue
            # Only require uppercase start for multi-word names extracted by NLP (not regex)
            if wcount > 1 and not _starts_uppercase(value) and "regex" not in entity.sources:
                logger.debug("[PP] DROP name %r -- no leading uppercase", value)
                continue
            # Reject section-header patterns
            if _SECTION_HEADER.match(value):
                logger.debug("[PP] DROP name %r -- section header pattern", value)
                continue
            # Reject noisy OCR fragments: values with embedded newlines/numbers are noise
            if re.search(r"[\n\r]|(\d{3,})", value):
                logger.debug("[PP] DROP name %r -- embedded newline or numeric noise", value[:40])
                continue

        elif ptype == "father_name":
            if vlower in _NAME_STOPWORDS:
                logger.debug("[PP] DROP father_name %r -- stopword", value)
                continue
            if wcount == 1 and value == value.lower():
                logger.debug("[PP] DROP father_name %r -- all lowercase single word", value)
                continue
            if _is_mostly_lowercase_sentence(value):
                logger.debug("[PP] DROP father_name %r -- looks like a sentence", value[:40])
                continue
            # Reject if it contains noise characters typical of OCR artifacts
            if re.search(r"[\n\r]|(\d{3,})", value):
                logger.debug("[PP] DROP father_name %r -- embedded newline or numeric noise", value[:40])
                continue

        elif ptype == "organization":
            if _is_mostly_lowercase_sentence(value):
                logger.debug("[PP] DROP org %r -- looks like a sentence", value[:40])
                continue
            if _SECTION_HEADER.match(value):
                logger.debug("[PP] DROP org %r -- section header", value)
                continue

        elif ptype == "diagnosis":
            # Must look clinical
            if not _CLINICAL_INDICATORS.search(value):
                if _is_mostly_lowercase_sentence(value):
                    logger.debug("[PP] DROP diagnosis %r -- not clinical", value[:40])
                    continue
                if wcount > 4:
                    logger.debug("[PP] DROP diagnosis %r -- no clinical marker", value[:40])
                    continue

        # ── 4. Drug canonicalization -> medication type ───────────────────────
        drug_canonical = _KNOWN_DRUGS.get(vlower)
        if drug_canonical:
            drug_entities.append(ResolvedEntity(
                pii_type="medication",
                value=entity.value,
                confidence=max(conf, 0.90),
                sources=entity.sources,
                start=entity.start,
                end=entity.end,
                context=entity.context,
                sensitivity="High",
                metadata={
                    **entity.metadata,
                    "original_type": ptype,
                    "canonical_medication": drug_canonical,
                },
            ))
            logger.debug("[PP] RECLASSIFY %s %r -> medication", ptype, value)
            continue

        kept.append(entity)

    # ── 5. Dedup medication entities by canonical name ────────────────────────
    seen_drugs: set[str] = set()
    for de in drug_entities:
        drug_key = de.metadata.get("canonical_medication", de.value)
        if drug_key not in seen_drugs:
            seen_drugs.add(drug_key)
            kept.append(de)

    # ── 6. Sort: sensitivity desc, confidence desc ────────────────────────────
    from constants import SENSITIVITY_ORDER
    kept.sort(key=lambda e: (
        -SENSITIVITY_ORDER.get(e.sensitivity, 1),
        -e.confidence,
    ))

    dropped = len(resolved) - len(kept) + len(drug_entities)
    logger.info("[POST-PROCESS] %d -> %d entities (%d dropped, %d reclassified as medication)",
                len(resolved), len(kept), dropped, len(seen_drugs))

    _assert_entity_evidence_immutable(resolved, kept, immutable_spans)
    return kept


def _assert_entity_evidence_immutable(before: list, after: list, snapshots: dict) -> None:
    """Post-processing may filter/reclassify, but evidence value/span stay fixed."""
    for entity in before:
        original = snapshots.get(id(entity))
        if original and (entity.value, entity.start, entity.end) != original:
            raise AssertionError("post_processor mutated input entity evidence")

    for entity in after:
        if entity.metadata.get("original_type"):
            continue
        original = snapshots.get(id(entity))
        if original and (entity.value, entity.start, entity.end) != original:
            raise AssertionError("post_processor mutated output entity evidence")
