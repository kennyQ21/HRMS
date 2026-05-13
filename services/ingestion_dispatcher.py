"""
services/ingestion_dispatcher.py
----------------------------------
Ingestion Dispatcher — routing layer between the API and parsers.

Simplified architecture:
  - No per-ID-card doc types (regex detects them directly)
  - Only 4 document profiles: generic, medical, structured, ocr_heavy
  - Lightweight medical routing (different NLP thresholds + compliance)
  - Everything else is generic
"""

from __future__ import annotations

import logging
import os
import re
from dataclasses import dataclass, field
from typing import Optional

logger = logging.getLogger(__name__)

# ── Medical keyword detection (only domain that needs special routing) ────────

MEDICAL_KEYWORDS = re.compile(
    r"(?i)\b(?:patient|hospital|clinic|diagnosis|prescription|discharge|"
    r"medical|health|lab\s*report|radiology|pathology|doctor|physician|"
    r"insurance\s*claim|icd|cpt|medication|dosage|allergy|vitals|ehr|"
    r"abha|ayushman|weight|height|blood\s*(?:group|pressure|sugar)|"
    r"hemoglobin|cholesterol|creatinine|glucose|mrn)\b"
)


@dataclass
class DocumentProfile:
    """
    Simplified document profile replacing the old doc_type string.

    Drives downstream engine routing without brittle per-ID-card types.
    Regex already detects Aadhaar/PAN/passport/etc. directly — no need
    for the ingestion layer to classify them.
    """
    is_structured:    bool = False   # CSV/XLSX/MDB — column-level scanning
    needs_ocr:        bool = False   # Image or scanned PDF
    is_medical:       bool = False   # Medical NLP thresholds + compliance
    is_multilingual:  bool = False   # Triggers Qwen NER routing


@dataclass
class IngestionPlan:
    """
    Complete routing plan produced by IngestionDispatcher for one file.

    Consumed by:
      - routers/scan.py (parser selection, OCR flag)
      - DetectionDispatcher (document_profile for engine routing)
      - ContentReconstruction (chunking_mode)
    """
    filename:         str
    extension:        str                     # lower, with dot — e.g. ".pdf"
    parser_type:      str                     # "pdf" | "docx" | "csv" | "xlsx" | "image" | ...
    document_profile: DocumentProfile = field(default_factory=DocumentProfile)
    chunking_mode:    str    = "full"         # "full"|"page"|"paragraph"|"row"
    password:         Optional[str] = None
    rationale:        list[str] = field(default_factory=list)   # audit trail

    # Backward-compatible property for code that still reads .doc_type
    @property
    def doc_type(self) -> str:
        if self.document_profile.is_medical:
            return "medical"
        if self.document_profile.is_structured:
            return "structured"
        if self.document_profile.needs_ocr:
            return "ocr_heavy"
        return "generic"


# ── Supported extension → parser type map ────────────────────────────────────

_EXT_TO_PARSER: dict[str, str] = {
    ".pdf":   "pdf",
    ".docx":  "docx",
    ".doc":   "doc",
    ".odt":   "odt",
    ".rtf":   "rtf",
    ".csv":   "csv",
    ".xlsx":  "xlsx",
    ".xls":   "xlsx",
    ".mdb":   "mdb",
    ".sql":   "sql",
    ".jpg":   "image",
    ".jpeg":  "image",
    ".png":   "image",
    ".bmp":   "image",
    ".tif":   "image",
    ".tiff":  "image",
    ".webp":  "image",
    ".pptx":  "pptx",
    ".zip":   "zip",
}

_STRUCTURED_PARSERS: set[str] = {"csv", "xlsx", "mdb"}
_IMAGE_PARSERS:      set[str] = {"image"}
_DOCUMENT_PARSERS:   set[str] = {"pdf", "docx", "doc", "odt", "rtf", "sql"}


class IngestionDispatcher:
    """
    Analyses an uploaded file and produces a complete IngestionPlan.

    Call dispatch() before touching any parser — the plan drives every
    downstream decision.
    """

    def dispatch(
        self,
        file_path: str,
        filename: str,
        password: Optional[str] = None,
    ) -> IngestionPlan:
        ext      = os.path.splitext(filename.lower())[1]
        parser_t = _EXT_TO_PARSER.get(ext, "unknown")
        rationale: list[str] = [f"extension={ext} -> parser={parser_t}"]

        profile = DocumentProfile(
            is_structured=parser_t in _STRUCTURED_PARSERS,
        )

        plan = IngestionPlan(
            filename=filename,
            extension=ext,
            parser_type=parser_t,
            document_profile=profile,
            password=password,
        )

        if parser_t == "unknown":
            rationale.append("UNSUPPORTED format -- will return error")
            plan.rationale = rationale
            return plan

        # ── OCR flags ────────────────────────────────────────────────────────
        if parser_t == "image":
            profile.needs_ocr = True
            rationale.append("image -> OCR mandatory, bbox enabled for redaction")

        elif parser_t == "pdf":
            is_scanned = self._pdf_needs_ocr(file_path)
            profile.needs_ocr = is_scanned
            if is_scanned:
                rationale.append("PDF text layer sparse -> OCR fallback")
            else:
                rationale.append("PDF has text layer -> direct extraction")

        # ── Chunking mode ─────────────────────────────────────────────────────
        if parser_t == "pdf":
            plan.chunking_mode = "page"
        elif parser_t in {"csv", "xlsx", "mdb"}:
            plan.chunking_mode = "row"
        elif parser_t in {"docx", "doc", "odt", "rtf"}:
            plan.chunking_mode = "paragraph"
        else:
            plan.chunking_mode = "full"

        # ── Medical detection (only domain that needs special routing) ────────
        snippet = self._read_text_snippet(file_path, parser_t)
        check_text = f"{filename} {snippet}".lower()

        if MEDICAL_KEYWORDS.search(check_text):
            profile.is_medical = True
            med_hits = len(MEDICAL_KEYWORDS.findall(check_text))
            rationale.append(f"medical keywords detected ({med_hits} hits) -> medical routing")
        else:
            rationale.append("no domain keywords -> generic routing")

        plan.rationale = rationale
        logger.info(
            "[INGESTION] %s -> parser=%s ocr=%s medical=%s structured=%s chunking=%s",
            filename, parser_t, profile.needs_ocr, profile.is_medical,
            profile.is_structured, plan.chunking_mode,
        )
        return plan

    # ── OCR check ─────────────────────────────────────────────────────────────

    def _pdf_needs_ocr(self, file_path: str) -> bool:
        """Return True if PDF text layer is too sparse to trust."""
        try:
            import PyPDF2
            with open(file_path, "rb") as f:
                reader = PyPDF2.PdfReader(f)
                if reader.is_encrypted:
                    return False
                total_text = 0
                pages_checked = min(len(reader.pages), 3)
                for page in reader.pages[:pages_checked]:
                    t = page.extract_text() or ""
                    total_text += len(t.strip())
                return total_text < 150 * pages_checked
        except Exception:
            return False

    # ── Text snippet for content-based classification ────────────────────────

    def _read_text_snippet(self, file_path: str, parser_t: str) -> str:
        """Extract first ~1000 chars of text for heuristic classification."""
        try:
            if parser_t == "pdf":
                import PyPDF2
                with open(file_path, "rb") as f:
                    reader = PyPDF2.PdfReader(f)
                    if not reader.is_encrypted and reader.pages:
                        return (reader.pages[0].extract_text() or "")[:1000]
            elif parser_t in {"docx"}:
                import docx
                doc = docx.Document(file_path)
                return "\n".join(p.text for p in doc.paragraphs[:20])[:1000]
            elif parser_t == "csv":
                with open(file_path, "r", errors="replace") as f:
                    return f.read(1000)
        except Exception:
            pass
        return ""


# ── Module-level singleton ────────────────────────────────────────────────────

_ingestion_dispatcher = IngestionDispatcher()


def dispatch_ingestion(
    file_path: str,
    filename: str,
    password: Optional[str] = None,
) -> IngestionPlan:
    return _ingestion_dispatcher.dispatch(file_path, filename, password)
