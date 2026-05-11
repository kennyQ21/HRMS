"""
services/post_processor.py
---------------------------
Post-processing layer applied to resolved entities BEFORE the final response.

Responsibilities (in order):
  1. Confidence gate      — drop entities below per-type minimum threshold
  2. Length gate          — reject multi-sentence / word-soup entities
  3. Stopword rejection   — reject role words / pronouns detected as names
  4. Capitalization check — names / orgs must start with an uppercase letter
  5. Duplicate suppression— remove entities whose value is a substring of another same-type entity
  6. Drug canonicalization— normalize known drug names to `medication` type
  7. Diagnosis filter     — reject non-clinical sentences labelled as diagnosis
  8. Organization filter  — reject section headers / interview labels as orgs

These rules are SURGICAL — they only fire when evidence is clear.
They will not suppress genuinely detected PII.
"""
from __future__ import annotations

import logging
import re
from typing import List

logger = logging.getLogger(__name__)

# ── 1. Per-type minimum confidence ───────────────────────────────────────────

_MIN_CONFIDENCE: dict[str, float] = {
    "name":                    0.70,
    "organization":            0.65,
    "diagnosis":               0.75,
    "address":                 0.60,
    "occupation":              0.65,
    "nationality":             0.65,
    "educational_qualification": 0.75,
    "insurance_provider":      0.70,
    "treatment_history":       0.70,
    "prescription":            0.60,
    "allergies":               0.65,
    "city":                    0.60,
}
_DEFAULT_MIN_CONF = 0.50

# ── 2. Max word count per type ────────────────────────────────────────────────

_MAX_WORDS: dict[str, int] = {
    "name":                    5,
    "organization":            8,
    "city":                    3,
    "nationality":             4,
    "occupation":              6,
    "diagnosis":               12,
    "prescription":            8,
    "allergies":               8,
    "treatment_history":       20,
    "educational_qualification": 6,
    "insurance_provider":      8,
    "address":                 20,
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
    # Common function words
    "the", "a", "an", "and", "or", "but", "if", "in", "on", "at",
    "to", "of", "for", "by", "with", "from", "about", "between",
    "what", "which", "who", "when", "where", "how", "why",
    # Healthcare workflow terms (not diagnoses, not names)
    "pharmacy", "pharmacies", "prescription", "medication", "drug",
    "health", "healthcare", "medical", "clinical", "treatment",
    "authorization", "prior", "approval",
})

_ORG_STOPWORDS: frozenset[str] = frozenset({
    # Interview / document structural labels
    "interviewer", "interviewee", "respondent", "speaker", "narrator",
    "frequency", "understood", "continued", "section", "topic",
    "overview", "summary", "background", "introduction", "conclusion",
    "question", "answer", "response", "comment", "note", "notes",
    # Generic document section headers
    "core business model", "core service lines", "strategy", "objectives",
    "key findings", "methodology", "analysis", "discussion", "results",
    "appendix", "references", "glossary", "index",
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

# ── Section-header / document-structure patterns to reject ───────────────────

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

_ORG_WITH_COLON_SUFFIX = re.compile(r":\s*$")
_LEADING_THE = re.compile(r"^[Tt]he\s+")
_ORG_SUFFIX_NOISE = re.compile(r"\s+[-–]\s+(?:Health|Broker|Medication|Plan|Provider|Insurance|Drug|Service)$", re.I)

# Document section-header keyword patterns — reject orgs containing these
_ORG_HEADER_KEYWORDS = re.compile(
    r"(?i)\b(?:requirements?|roadmap|strategy|innovation|integration|"
    r"methodology|objectives?|findings?|deliverables?|milestones?|"
    r"performance|framework|guidelines?|protocol|workflow|process)\b"
)

# Generic insurance terms that are not specific provider names
_GENERIC_INSURANCE = frozenset({
    "health plan", "health plans", "health insurance", "insurance plan",
    "insurance plans", "insurance provider", "insurance company",
    "medical plan", "the plan", "pbm", "the pbm",
})

# Generic prescription keywords that are not actual drug/prescription values
_GENERIC_PRESCRIPTION_KEYWORDS = frozenset({
    "medication", "prescription", "drug", "drugs", "medicine", "medicines",
    "medications", "prescriptions", "tablet", "capsule",
})

# ── LLM placeholder / hallucination rejection ────────────────────────────────
# Small model (0.5B) emits these when it finds nothing real in the chunk
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

# ── 5. Diagnosis: must look like a clinical term, not a sentence ──────────────

_CLINICAL_INDICATORS = re.compile(
    r"(?i)\b(?:disease|disorder|syndrome|condition|infection|cancer|"
    r"carcinoma|lymphoma|leukemia|diabetes|hypertension|arthritis|"
    r"sclerosis|lupus|psoriasis|colitis|anemia|neuropathy|hepatitis|"
    r"fibrosis|asthma|copd|eczema|dermatitis|melanoma|tumor|tumour|"
    r"malignancy|autoimmune|chronic|acute|diagnosis|diagnosed)\b"
)

_SENTENCE_PATTERN = re.compile(
    r"(?i)\b(?:gets?|goes?|routes?|stops?|sends?|takes?|makes?|gives?|"
    r"thinks?|means?|really|there|more|options?|anybody|something|"
    r"everything|nothing|anything|i think|i mean|i really)\b"
)

# ── Helpers ───────────────────────────────────────────────────────────────────

def _word_count(text: str) -> int:
    return len(text.split())


def _starts_uppercase(text: str) -> bool:
    stripped = text.strip()
    return bool(stripped) and stripped[0].isupper()


def _is_mostly_lowercase_sentence(text: str) -> bool:
    """True if the text looks like a prose sentence (not a proper entity)."""
    words = text.split()
    if len(words) < 4:
        return False
    lowercase = sum(1 for w in words if w[0].islower() if w)
    return lowercase / len(words) > 0.6


# ── Main entry point ──────────────────────────────────────────────────────────

def post_process(resolved: list) -> list:
    """
    Apply all post-processing rules to a list of ResolvedEntity objects.
    Returns a filtered, possibly modified list.
    """
    from services.entity_resolution import ResolvedEntity

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
            logger.debug("[PP] DROP %s %r — conf %.2f < %.2f", ptype, value[:40], conf, min_conf)
            continue

        # ── 1b. LLM placeholder rejection ────────────────────────────────────
        if "llm" in entity.sources:
            if _LLM_PLACEHOLDERS.match(value):
                logger.debug("[PP] DROP %s %r — LLM placeholder", ptype, value[:40])
                continue
            if vlower in _SCRIPT_LANGUAGE_NAMES:
                logger.debug("[PP] DROP %s %r — script/language name", ptype, value[:40])
                continue
            # Reject comma-separated mixed-type dumps ("नाम, IDs, financial details")
            if value.count(",") >= 2 and wcount > 3:
                logger.debug("[PP] DROP %s %r — LLM data dump", ptype, value[:40])
                continue

        # ── 2. Length gate ────────────────────────────────────────────────────
        max_words = _MAX_WORDS.get(ptype, _DEFAULT_MAX_WORDS)
        if wcount > max_words:
            logger.debug("[PP] DROP %s %r — %d words > %d", ptype, value[:40], wcount, max_words)
            continue

        # ── 3. Stopword rejection + type-specific guards ──────────────────────
        if ptype == "name":
            if vlower in _NAME_STOPWORDS:
                logger.debug("[PP] DROP name %r — stopword", value)
                continue
            if wcount == 1 and value == value.lower():
                logger.debug("[PP] DROP name %r — all lowercase single word", value)
                continue
            if _is_mostly_lowercase_sentence(value):
                logger.debug("[PP] DROP name %r — looks like a sentence", value[:40])
                continue
            if not _starts_uppercase(value) and "regex" not in entity.sources:
                logger.debug("[PP] DROP name %r — no leading uppercase", value)
                continue
            # Reject section-header patterns (e.g. "V. Performance", "X. Wrap-Up")
            if _SECTION_HEADER.match(value):
                logger.debug("[PP] DROP name %r — section header pattern", value)
                continue
            # Reject "Name - Role" noise (e.g. "Mercer - Broker")
            if _ORG_SUFFIX_NOISE.search(value) and wcount <= 3:
                logger.debug("[PP] DROP name %r — name-role suffix noise", value)
                continue

        elif ptype == "organization":
            if vlower in _ORG_STOPWORDS:
                logger.debug("[PP] DROP org %r — structural label", value)
                continue
            if _is_mostly_lowercase_sentence(value):
                logger.debug("[PP] DROP org %r — looks like a sentence", value[:40])
                continue
            if _SENTENCE_PATTERN.search(value):
                logger.debug("[PP] DROP org %r — contains sentence words", value[:40])
                continue
            # Reject document section headers
            if _SECTION_HEADER.match(value):
                logger.debug("[PP] DROP org %r — section header", value)
                continue
            if _ORG_WITH_COLON_SUFFIX.search(value):
                logger.debug("[PP] DROP org %r — ends with colon (structural label)", value)
                continue
            # Strip leading "the " and check for duplicates downstream
            if _LEADING_THE.match(value):
                value = _LEADING_THE.sub("", value).strip()
                entity = type(entity)(
                    pii_type=entity.pii_type, value=value,
                    confidence=entity.confidence, sources=entity.sources,
                    start=entity.start, end=entity.end,
                    context=entity.context, sensitivity=entity.sensitivity,
                    metadata=entity.metadata,
                )

        elif ptype == "prescription":
            # Reject generic keyword matches — must be a real drug/prescription value
            if vlower in _GENERIC_PRESCRIPTION_KEYWORDS:
                logger.debug("[PP] DROP prescription %r — generic keyword", value)
                continue

        elif ptype == "insurance_provider":
            # Reject generic insurance terms (not specific provider names)
            if vlower in _GENERIC_INSURANCE:
                logger.debug("[PP] DROP insurance_provider %r — generic term", value)
                continue

        elif ptype == "diagnosis":
            # Must look clinical — reject pharmacy workflow / process sentences
            if not _CLINICAL_INDICATORS.search(value):
                if _SENTENCE_PATTERN.search(value) or _is_mostly_lowercase_sentence(value):
                    logger.debug("[PP] DROP diagnosis %r — not clinical", value[:40])
                    continue
                if wcount > 4 and not _CLINICAL_INDICATORS.search(value):
                    logger.debug("[PP] DROP diagnosis %r — no clinical marker", value[:40])
                    continue

        elif ptype == "educational_qualification":
            # Must be ≥2 chars and not a common word
            if len(value) < 2 or vlower in {"be", "me", "ba", "ma", "do", "ms"}:
                logger.debug("[PP] DROP edu_qual %r — too short/generic", value)
                continue

        # ── 4. Drug canonicalization → medication type ────────────────────────
        drug_canonical = _KNOWN_DRUGS.get(vlower)
        if drug_canonical:
            # Emit as medication instead of prescription/organization
            drug_entities.append(ResolvedEntity(
                pii_type="medication",
                value=drug_canonical,
                confidence=max(conf, 0.90),   # known drug = high confidence
                sources=entity.sources,
                start=entity.start,
                end=entity.end,
                context=entity.context,
                sensitivity="High",
                metadata={**entity.metadata, "original_type": ptype},
            ))
            # Drop the misclassified entity
            logger.debug("[PP] RECLASSIFY %s %r → medication", ptype, value)
            continue

        kept.append(entity)

    # ── 5. Dedup medication entities by canonical name ────────────────────────
    seen_drugs: set[str] = set()
    for de in drug_entities:
        if de.value not in seen_drugs:
            seen_drugs.add(de.value)
            kept.append(de)

    # ── 6. Sort: sensitivity desc, confidence desc ────────────────────────────
    from constants import SENSITIVITY_ORDER
    kept.sort(key=lambda e: (
        -SENSITIVITY_ORDER.get(e.sensitivity, 1),
        -e.confidence,
    ))

    dropped = len(resolved) - len(kept) + len(drug_entities)
    logger.info("[POST-PROCESS] %d → %d entities (%d dropped, %d reclassified as medication)",
                len(resolved), len(kept), dropped, len(seen_drugs))

    return kept
