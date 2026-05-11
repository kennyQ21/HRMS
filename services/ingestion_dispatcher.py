"""
services/ingestion_dispatcher.py
----------------------------------
Ingestion Dispatcher — the formal routing layer between the API and parsers.

Replaces the ad-hoc _get_parser() logic in routers/files.py with a
structured, observable, strategy-aware routing system.

Responsibilities:
  • Parser selection      — chooses the right parser for each file type
  • OCR necessity         — detects scanned PDFs, image-heavy documents
  • Document strategy     — sets chunking mode and detection doc_type hint
  • Semantic routing      — tags medical / financial / HR / ID documents
  • Observability         — logs every routing decision with rationale

Route decisions:
  ┌──────────────────────────────────────────────────────────┐
  │  File Type          Strategy       doc_type hint         │
  │  ─────────────────────────────────────────────────────   │
  │  Scanned PDF        OCR-heavy      auto-detected         │
  │  Digital PDF        text-layer     auto-detected         │
  │  XLSX (financial)   structured     financial             │
  │  DOCX (medical)     full-text      medical               │
  │  Image (ID card)    OCR + bbox     id                    │
  │  CSV                structured     generic               │
  │  SQL                full-text      generic               │
  │  MDB                structured     generic               │
  └──────────────────────────────────────────────────────────┘
"""

from __future__ import annotations

import logging
import os
import re
from dataclasses import dataclass, field
from typing import Optional

logger = logging.getLogger(__name__)

# ── Document type keyword heuristics ─────────────────────────────────────────

_MEDICAL_KEYWORDS = re.compile(
    r"(?i)\b(?:patient|hospital|clinic|diagnosis|prescription|discharge|"
    r"medical|health|lab\s*report|radiology|pathology|doctor|physician|"
    r"insurance\s*claim|icd|cpt|medication|dosage|allergy|vitals|ehr)\b"
)
_FINANCIAL_KEYWORDS = re.compile(
    r"(?i)\b(?:invoice|receipt|balance\s*sheet|profit|loss|tax|salary|"
    r"payslip|bank\s*statement|transaction|account\s*number|gst|pan|"
    r"income|expense|ledger|journal|audit|financial|credit|debit|upi)\b"
)
_HR_KEYWORDS = re.compile(
    r"(?i)\b(?:employee|resume|cv|curriculum\s*vitae|offer\s*letter|"
    r"payroll|appraisal|designation|department|joining|termination|"
    r"interview|onboarding|hr|human\s*resource)\b"
)
_ID_KEYWORDS = re.compile(
    r"(?i)\b(?:aadhaar|passport|driving\s*licen[cs]e|voter|pan\s*card|"
    r"identity|national\s*id|id\s*card|uid)\b"
)

# Specific identity document classifiers (checked after generic _ID_KEYWORDS)
_AADHAAR_SIGNALS = re.compile(
    r"(?i)\b(?:aadhaar|uidai|unique\s*identification\s*authority|"
    r"आधार|আধার|ಆಧಾರ್|ஆதார்|ఆధార్)\b"
)
_PAN_SIGNALS = re.compile(
    r"(?i)\b(?:permanent\s*account\s*number|income\s*tax\s*department|"
    r"pan\s*card)\b"
)
_PASSPORT_SIGNALS = re.compile(
    r"(?i)\b(?:republic\s*of|ministry\s*of\s*external|passport\s*no|"
    r"nationality|place\s*of\s*birth|date\s*of\s*issue)\b"
)
_VOTER_SIGNALS = re.compile(
    r"(?i)\b(?:election\s*commission|elector\s*photo|epic|voter\s*id|"
    r"electoral\s*roll)\b"
)
_DL_SIGNALS = re.compile(
    r"(?i)\b(?:driving\s*licen[cs]e|motor\s*vehicles|transport\s*department|"
    r"dl\s*no|licence\s*no)\b"
)


@dataclass
class IngestionPlan:
    """
    Complete routing plan produced by IngestionDispatcher for one file.

    Consumed by:
      - routers/files.py (parser selection, OCR flag)
      - DetectionDispatcher (doc_type hint for engine routing)
      - ContentReconstruction (chunking_mode)
    """
    filename:      str
    extension:     str                     # lower, with dot — e.g. ".pdf"
    parser_type:   str                     # "pdf" | "docx" | "csv" | "xlsx" | "image" | ...
    needs_ocr:     bool   = False          # True → run OCR pipeline
    ocr_with_bbox: bool   = False          # True → extract bounding boxes (for redaction)
    doc_type:      str    = "generic"      # "medical"|"financial"|"hr"|"id"|"generic"
    chunking_mode: str    = "full"         # "full"|"page"|"paragraph"|"row"
    is_structured: bool   = False          # True → column-level scanning (CSV/XLSX/MDB)
    password:      Optional[str] = None
    rationale:     list[str] = field(default_factory=list)   # audit trail


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
        filename_hint: Optional[str] = None,
    ) -> IngestionPlan:
        """
        Produce a routing plan for the given file.

        Args:
            file_path:     Absolute path to the saved temp file.
            filename:      Original upload filename (used for extension + hints).
            password:      Optional password for encrypted PDFs / ZIPs.
            filename_hint: Optional override for doc-type detection from filename.
        """
        ext      = os.path.splitext(filename.lower())[1]
        parser_t = _EXT_TO_PARSER.get(ext, "unknown")
        rationale: list[str] = [f"extension={ext} → parser={parser_t}"]

        plan = IngestionPlan(
            filename=filename,
            extension=ext,
            parser_type=parser_t,
            password=password,
            is_structured=parser_t in _STRUCTURED_PARSERS,
        )

        if parser_t == "unknown":
            rationale.append("UNSUPPORTED format — will return error")
            plan.rationale = rationale
            return plan

        # ── OCR flags ────────────────────────────────────────────────────────
        if parser_t == "image":
            plan.needs_ocr     = True
            plan.ocr_with_bbox = True
            rationale.append("image → OCR mandatory, bbox enabled for redaction")

        elif parser_t == "pdf":
            is_scanned = self._pdf_needs_ocr(file_path)
            plan.needs_ocr = is_scanned
            if is_scanned:
                rationale.append("PDF text layer sparse → OCR fallback")
            else:
                rationale.append("PDF has text layer → direct extraction")

        # ── Chunking mode ─────────────────────────────────────────────────────
        if parser_t == "pdf":
            plan.chunking_mode = "page"
        elif parser_t in {"csv", "xlsx", "mdb"}:
            plan.chunking_mode = "row"
        elif parser_t in {"docx", "doc", "odt", "rtf"}:
            plan.chunking_mode = "paragraph"
        else:
            plan.chunking_mode = "full"

        # ── Doc-type detection ────────────────────────────────────────────────
        name_for_hint = filename_hint or filename
        doc_type, dt_rationale = self._detect_doc_type(file_path, name_for_hint, parser_t)
        plan.doc_type = doc_type
        rationale.append(dt_rationale)

        plan.rationale = rationale
        logger.info(
            "[INGESTION] %s → parser=%s ocr=%s doc_type=%s chunking=%s | %s",
            filename, parser_t, plan.needs_ocr, doc_type,
            plan.chunking_mode, "; ".join(rationale),
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
                    return False   # can't peek; let PDFParser handle it
                total_text = 0
                pages_checked = min(len(reader.pages), 3)
                for page in reader.pages[:pages_checked]:
                    t = page.extract_text() or ""
                    total_text += len(t.strip())
                needs = total_text < 150 * pages_checked
                return needs
        except Exception:
            return False

    # ── Doc-type heuristics ───────────────────────────────────────────────────

    def _detect_doc_type(
        self, file_path: str, filename: str, parser_t: str
    ) -> tuple[str, str]:
        """
        Return (doc_type, rationale_string).

        Strategy:
          1. Filename keywords (fast, zero I/O)
          2. First-N-chars of file content (for text files only)
        """
        fname_lower = filename.lower()

        # Filename-based detection — specific ID types first
        if _AADHAAR_SIGNALS.search(fname_lower):
            return "aadhaar_card", "filename contains Aadhaar signals"
        if _PAN_SIGNALS.search(fname_lower):
            return "pan_card", "filename contains PAN card signals"
        if _PASSPORT_SIGNALS.search(fname_lower):
            return "passport", "filename contains passport signals"
        if _VOTER_SIGNALS.search(fname_lower):
            return "voter_id", "filename contains voter ID signals"
        if _DL_SIGNALS.search(fname_lower):
            return "driving_license", "filename contains driving licence signals"
        if _MEDICAL_KEYWORDS.search(fname_lower):
            return "medical", "filename contains medical keywords"
        if _FINANCIAL_KEYWORDS.search(fname_lower):
            return "financial", "filename contains financial keywords"
        if _HR_KEYWORDS.search(fname_lower):
            return "hr", "filename contains HR keywords"
        if _ID_KEYWORDS.search(fname_lower):
            return "id", "filename contains ID-document keywords"

        # Content-based detection (only for text-extractable types)
        if parser_t in _DOCUMENT_PARSERS | {"docx", "doc", "odt", "rtf", "image"}:
            snippet = self._read_text_snippet(file_path, parser_t)
            if snippet:
                # Check specific ID document types first (highest confidence)
                if _AADHAAR_SIGNALS.search(snippet):
                    return "aadhaar_card", "content: Aadhaar/UIDAI signals found"
                if _PAN_SIGNALS.search(snippet):
                    return "pan_card", "content: PAN card signals found"
                if _PASSPORT_SIGNALS.search(snippet):
                    return "passport", "content: passport signals found"
                if _VOTER_SIGNALS.search(snippet):
                    return "voter_id", "content: voter ID signals found"
                if _DL_SIGNALS.search(snippet):
                    return "driving_license", "content: driving licence signals found"

                med_hits = len(_MEDICAL_KEYWORDS.findall(snippet))
                fin_hits = len(_FINANCIAL_KEYWORDS.findall(snippet))
                hr_hits  = len(_HR_KEYWORDS.findall(snippet))
                id_hits  = len(_ID_KEYWORDS.findall(snippet))
                scores = {"medical": med_hits, "financial": fin_hits,
                          "hr": hr_hits, "id": id_hits}
                best = max(scores, key=lambda k: scores[k])
                if scores[best] >= 2:
                    return best, f"content heuristic: {best}={scores[best]} keyword hits"

        return "generic", "no domain keywords found → generic routing"

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
