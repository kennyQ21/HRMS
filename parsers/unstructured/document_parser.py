from __future__ import annotations

import logging
import os
import tempfile
from typing import Any, Dict, List

from ..base import BaseParser

logger = logging.getLogger(__name__)


def _run_ocr(img_paths: List[str], with_boxes: bool = False) -> List[dict]:
    """
    In-process OCR via ocr_worker.process_images().

    PaddleOCR models are loaded once per process (singleton in ocr_engine.py)
    and reused for all subsequent calls — no subprocess spawning, no model
    reload overhead.

    Returns one dict per path:  {"text": str, "lines": [[text, bbox], ...]}
    """
    if not img_paths:
        return []
    try:
        from services.ocr_worker import process_images
        return process_images(img_paths, with_boxes=with_boxes)
    except Exception as exc:
        logger.error("OCR failed: %s", exc)
        return [{"text": "", "lines": []} for _ in img_paths]


# ── DocumentParser ────────────────────────────────────────────────────────────

class DocumentParser(BaseParser):
    """
    Parses Word (.docx/.doc), ODT, and RTF documents.

    The text is returned *as-is* from the source.  PII detection and
    normalisation happen in a separate stage (process_document_content),
    never inside the parser.
    """

    def parse(self, file_path: str) -> Dict[str, Any]:
        ext = os.path.splitext(file_path)[1].lower()
        dispatch = {
            ".docx": self._parse_docx,
            ".doc":  self._parse_doc,
            ".odt":  self._parse_odt,
            ".rtf":  self._parse_rtf,
        }
        handler = dispatch.get(ext)
        if handler is None:
            raise ValueError(f"Unsupported document format: {ext}")
        return handler(file_path)

    def validate(self, data: Dict[str, Any]) -> bool:
        if not data or "data" not in data:
            return False
        if not data.get("data"):
            return False
        return all(k in data.get("metadata", {}) for k in ("columns", "rows"))

    # ── Format handlers ───────────────────────────────────────────────────────

    def _parse_docx(self, file_path: str) -> Dict[str, Any]:
        import docx

        text = ""
        try:
            doc = docx.Document(file_path)
            text = "\n\n".join(para.text for para in doc.paragraphs)
        except Exception as e:
            logger.error("Error extracting text from DOCX: %s", e)

        return self._build_result(text, "docx")

    def _parse_doc(self, file_path: str) -> Dict[str, Any]:
        import textract

        text = ""
        try:
            text = textract.process(file_path).decode("utf-8")
        except Exception as e:
            logger.error("Error extracting text from DOC: %s", e)

        return self._build_result(text, "doc")

    def _parse_odt(self, file_path: str) -> Dict[str, Any]:
        import odf.opendocument
        from odf.text import P

        text = ""
        try:
            doc = odf.opendocument.load(file_path)
            text = "\n\n".join(p.getText() for p in doc.getElementsByType(P))
        except Exception as e:
            logger.error("Error extracting text from ODT: %s", e)

        return self._build_result(text, "odt")

    def _parse_rtf(self, file_path: str) -> Dict[str, Any]:
        import striprtf.striprtf

        text = ""
        try:
            with open(file_path, "r", errors="replace") as f:
                text = striprtf.striprtf.rtf_to_text(f.read())
        except Exception as e:
            logger.error("Error extracting text from RTF: %s", e)

        return self._build_result(text, "rtf")

    # ── Shared ────────────────────────────────────────────────────────────────

    def _build_result(self, text: str, parser_name: str) -> Dict[str, Any]:
        """Return raw text without any mutation."""
        return {
            "data": [{"content": text}],
            "metadata": {
                "columns": ["content"],
                "rows": 1,
                "parser": parser_name,
            },
        }


# ── PDFParser ─────────────────────────────────────────────────────────────────

class PDFParser(BaseParser):
    """
    Parses PDF files using PyPDF2 for text-layer extraction, with an
    OCR fallback (via subprocess) for scanned/image-only PDFs.

    OCR via Azure Document Intelligence runs in a child process
    (services/ocr_worker.py) so any crash kills only the child — uvicorn is unaffected.
    """

    # DPI used when rasterising PDF pages for OCR.
    _OCR_DPI: int = 150

    def __init__(self, password: str | None = None):
        super().__init__()
        self.password = password

    def parse(self, file_path: str) -> Dict[str, Any]:
        text = self._extract_text_layer(file_path)

        if len(text.strip()) < 100:
            logger.info("Text layer sparse — falling back to OCR for %s", file_path)
            ocr_text = self._extract_text_via_ocr(file_path)
            if len(ocr_text.strip()) > len(text.strip()):
                text = ocr_text

        return {
            "data": [{"content": text}],
            "metadata": {
                "columns": ["content"],
                "rows": 1,
                "parser": "pdf_ocr",
            },
        }

    def validate(self, data: Dict[str, Any]) -> bool:
        if not data or "data" not in data:
            return False
        if not data.get("data"):
            return False
        return all(k in data.get("metadata", {}) for k in ("columns", "rows"))

    # ── Text-layer extraction ─────────────────────────────────────────────────

    def _extract_text_layer(self, file_path: str) -> str:
        import PyPDF2

        text = ""
        try:
            with open(file_path, "rb") as f:
                reader = PyPDF2.PdfReader(f)

                if reader.is_encrypted:
                    if not self.password:
                        raise ValueError("PDF is password protected. Password required.")
                    result = reader.decrypt(self.password)
                    if result == 0:
                        raise ValueError("Incorrect PDF password provided.")

                for page in reader.pages:
                    page_text = page.extract_text()
                    if page_text:
                        text += page_text + "\n\n"

        except Exception as e:
            logger.error("Text-layer extraction failed: %s", e)
            raise

        return text

    # ── OCR extraction ────────────────────────────────────────────────────────

    def _extract_text_via_ocr(self, file_path: str) -> str:
        """
        Rasterise every page and OCR them all in a single subprocess call.

        All page images are saved to temp files, passed to ocr_worker.py
        together (one model load for all pages), then the temp files are
        cleaned up.  If the worker crashes the function returns "".
        """
        from pdf2image import convert_from_path

        try:
            images = (
                convert_from_path(file_path, dpi=self._OCR_DPI, userpw=self.password)
                if self.password
                else convert_from_path(file_path, dpi=self._OCR_DPI)
            )
        except Exception as e:
            logger.error("pdf2image conversion failed: %s", e)
            return ""

        tmp_paths: list[str] = []
        try:
            for pil_img in images:
                with tempfile.NamedTemporaryFile(suffix=".png", delete=False) as f:
                    tmp_paths.append(f.name)
                pil_img.save(tmp_paths[-1])

            results = _run_ocr(tmp_paths, with_boxes=False)
            page_texts = [r.get("text", "") for r in results]
            return "\n\n".join(t for t in page_texts if t)

        finally:
            for p in tmp_paths:
                try:
                    os.unlink(p)
                except OSError:
                    pass


# ── ImageParser ───────────────────────────────────────────────────────────────

class ImageParser(PDFParser):
    """
    OCR parser for standalone image files (JPG/PNG/BMP/TIFF/WEBP).

    All OCR runs in a subprocess (services/ocr_worker.py) so a crash
    cannot take down the main service process.
    """

    def parse(self, file_path: str) -> Dict[str, Any]:
        results = _run_ocr([file_path], with_boxes=False)
        text = results[0].get("text", "") if results else ""
        return {
            "data": [{"content": text}],
            "metadata": {
                "columns": ["content"],
                "rows": 1,
                "parser": "image_ocr",
            },
        }

    def parse_with_boxes(self, file_path: str) -> Dict[str, Any]:
        """
        Like parse() but also returns per-line bounding boxes.

        bbox coords are in original-image pixel space (the worker handles
        the resize-and-scale-back internally).
        """
        results = _run_ocr([file_path], with_boxes=True)
        data = results[0] if results else {"text": "", "lines": []}
        text = data.get("text", "")
        # Worker returns [[text_str, bbox_poly], ...]; convert to (text, bbox) tuples.
        lines = [(t, b) for t, b in data.get("lines", [])]
        logger.info(
            "OCR result for %s: %d chars, %d lines — preview: %r",
            file_path, len(text), len(lines), text[:120],
        )
        return {
            "data": [{"content": text}],
            "lines": lines,
            "ocr_quality": data.get("ocr_quality"),
            "metadata": {
                "columns": ["content"],
                "rows": 1,
                "parser": "image_ocr",
            },
        }
