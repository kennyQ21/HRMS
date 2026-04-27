from __future__ import annotations

import logging
import os
import re
from typing import Any, Dict

from ..base import BaseParser

logger = logging.getLogger(__name__)


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
    Parses PDF files using PyPDF2 for text-layer extraction, with a
    PaddleOCR fallback that applies cv2 image pre-processing to maximise
    accuracy on scanned pages.

    The PaddleOCR engine is initialised once in ``__init__`` so the deep-
    learning models are only loaded a single time regardless of how many
    pages the document contains.

    Text is returned *verbatim* — no PII normalization inside the parser.
    """

    # Minimum characters from one variant that means "good enough" —
    # skip remaining variants once this threshold is met.
    _MIN_GOOD_CHARS: int = 200

    # DPI used when rasterising PDF pages.  150 is sufficient for OCR and
    # produces images 4× smaller than 300 DPI, cutting processing time
    # dramatically on CPU.
    _OCR_DPI: int = 150

    # PaddleOCR segfaults on images with max side > 4000 px (SIGSEGV in its
    # internal resize).  Pre-resize to this limit before every predict() call.
    _MAX_OCR_SIDE: int = 3000

    def __init__(
        self,
        password: str | None = None,
    ):
        super().__init__()
        self.password = password

        # Suppress the "checking connectivity" delay on every cold start.
        import os
        os.environ.setdefault("PADDLE_PDX_DISABLE_MODEL_SOURCE_CHECK", "True")

        # Initialise PaddleOCR once — loading the models is expensive (~2-5 s).
        #
        # Both models are pinned to their *mobile* variants:
        #   • When text_detection_model_name is set, PaddleOCR ignores `lang`
        #     and defaults the recognition model to PP-OCRv5_server_rec (~80 MB).
        #     That model's native loader segfaults (SIGSEGV) on memory-constrained
        #     containers.  Pinning to PP-OCRv5_mobile_rec (~5 MB) avoids the crash.
        #   • mobile_det + mobile_rec together load ~3× faster and use far less RAM.
        from paddleocr import PaddleOCR  # deferred import
        self.ocr_engine = PaddleOCR(
            text_detection_model_name="PP-OCRv5_mobile_det",
            text_recognition_model_name="PP-OCRv5_mobile_rec",
            use_doc_orientation_classify=False,
            use_textline_orientation=False,
            use_doc_unwarping=False,
            enable_mkldnn=False,  # prevents OneDNN/PIR crash on CPU (paddlepaddle 3.3.x bug)
        )

    def parse(self, file_path: str) -> Dict[str, Any]:
        text = self._extract_text_layer(file_path)

        # If text layer is sparse (scanned PDF), fall back to OCR
        if len(text.strip()) < 100:
            logger.info("Text layer sparse — trying OCR for %s", file_path)
            ocr_text = self._extract_text_via_ocr(file_path)
            if len(ocr_text.strip()) > len(text.strip()):
                text = ocr_text

        return {
            "data": [{"content": text}],
            "metadata": {
                "columns": ["content"],
                "rows": 1,
                "parser": "pdf_paddleocr",
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
        Convert each PDF page to an image, apply cv2 preprocessing to produce
        multiple image variants, run PaddleOCR on every variant, and keep the
        result with the highest character count.

        CPU optimisations applied:
          1. Lower DPI (150 vs 300) — images are 4× smaller.
          2. Short-circuit variant loop — stop as soon as a variant yields
             >= _MIN_GOOD_CHARS characters (skips remaining preprocessing).
          3. Parallel page processing — pages are OCR'd concurrently using
             a ThreadPoolExecutor (safe: the engine is stateless per predict
             call; GIL is released during native inference).
        """
        import cv2
        import numpy as np
        from concurrent.futures import ThreadPoolExecutor, as_completed
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

        def _process_page(page_num: int, pil_image) -> str:
            """OCR a single page, short-circuiting once enough text found."""
            img_np = cv2.cvtColor(np.array(pil_image), cv2.COLOR_RGB2BGR)
            return self._extract_text_from_image_array(img_np, page_num)

        # Use up to 4 worker threads (I/O + native code releases the GIL).
        page_texts: dict[int, str] = {}
        with ThreadPoolExecutor(max_workers=4) as pool:
            futures = {
                pool.submit(_process_page, i, img): i
                for i, img in enumerate(images)
            }
            for future in as_completed(futures):
                page_num = futures[future]
                try:
                    page_texts[page_num] = future.result()
                except Exception as exc:  # noqa: BLE001
                    logger.warning("OCR failed on page %d: %s", page_num, exc)
                    page_texts[page_num] = ""

        # Reassemble in original page order.
        return "\n\n".join(page_texts[i] for i in sorted(page_texts))

    def _extract_text_from_image_array(self, img_np: "np.ndarray", page_num: int = 0) -> str:
        """
        OCR a single OpenCV image array and return the best variant output.
        """
        variants = self._preprocess_image(img_np)
        best = ""

        for idx, img_variant in enumerate(variants, start=1):
            candidate = self._run_paddle_ocr(img_variant, page_num)
            if len(candidate.strip()) > len(best.strip()):
                best = candidate

            if len(best.strip()) >= self._MIN_GOOD_CHARS:
                logger.debug(
                    "Page %d: good result after %d variant(s), skipping rest.",
                    page_num, idx,
                )
                break

        return best

    def _resize_for_ocr(self, img: "np.ndarray"):
        """
        Resize *img* so its longest side ≤ _MAX_OCR_SIDE.

        Returns (resized_img, scale_x, scale_y) where scale_x/y are the factors
        to multiply resized-space coordinates by to get back to original-image
        coordinates (used by the caller to un-project bounding boxes).
        """
        import cv2
        h, w = img.shape[:2]
        max_side = max(h, w)
        if max_side <= self._MAX_OCR_SIDE:
            return img, 1.0, 1.0
        scale = self._MAX_OCR_SIDE / max_side
        new_w = max(1, int(w * scale))
        new_h = max(1, int(h * scale))
        resized = cv2.resize(img, (new_w, new_h), interpolation=cv2.INTER_AREA)
        return resized, w / new_w, h / new_h

    def _run_paddle_ocr_with_boxes(self, img: "np.ndarray", page_num: int = 0):
        """
        Run OCR on *img* and return (full_text, lines).

        lines is a list of (text, bbox) where bbox is a list of 4 [x, y] points
        in the coordinate space of *img* (i.e. the original, un-preprocessed image).
        Always uses the original image so bounding boxes map directly to pixels.
        """
        img_resized, scale_x, scale_y = self._resize_for_ocr(img)
        try:
            results = list(self.ocr_engine.predict(img_resized))
            if not results:
                return "", []

            lines = []
            for ocr_result in results:
                texts = ocr_result.get("rec_texts", [])
                polys = ocr_result.get("dt_polys", [])
                for text, poly in zip(texts, polys):
                    if text and text.strip():
                        bbox = poly.tolist() if hasattr(poly, "tolist") else list(poly)
                        if scale_x != 1.0 or scale_y != 1.0:
                            bbox = [[int(p[0] * scale_x), int(p[1] * scale_y)] for p in bbox]
                        lines.append((text.strip(), bbox))

            full_text = "\n".join(t for t, _ in lines)
            return full_text, lines

        except Exception as e:
            logger.debug("PaddleOCR with boxes failed on page %d: %s", page_num, e)
            return "", []

    def _run_paddle_ocr(self, img: "np.ndarray", page_num: int = 0) -> str:
        """
        Run PaddleOCR on a single numpy image array and stitch the recognised
        text lines into a plain string.

        PaddleOCR v3 API:
            engine.predict(img) → generator of OCRResult objects.
            Each OCRResult is a dict-like object with keys:
                'rec_texts'  – list[str]  recognised text lines
                'rec_scores' – list[float] confidence per line
        """
        img, _, _ = self._resize_for_ocr(img)
        try:
            results = list(self.ocr_engine.predict(img))
            if not results:
                return ""

            lines = []
            for ocr_result in results:
                texts = ocr_result.get("rec_texts", [])
                lines.extend(t for t in texts if t and t.strip())

            return "\n".join(lines)

        except Exception as e:
            logger.debug("PaddleOCR failed on page %d: %s", page_num, e)
            return ""


    def _preprocess_image(self, img_np: "np.ndarray") -> list:
        """
        Apply a battery of cv2 transforms to a BGR numpy image and return
        all variants as numpy arrays (PaddleOCR's native input format).

        The caller passes a BGR numpy array (converted from PIL upstream).
        The first variant is always the original image so we never drop the
        baseline result even if all preprocessing steps fail.
        """
        import cv2
        import numpy as np

        variants = [img_np]  # baseline — original BGR image

        try:
            gray = cv2.cvtColor(img_np, cv2.COLOR_BGR2GRAY)

            # Otsu binarisation — best for high-contrast printed text
            _, otsu = cv2.threshold(gray, 0, 255, cv2.THRESH_BINARY + cv2.THRESH_OTSU)

            # Adaptive Gaussian threshold — handles uneven lighting / shadows
            adaptive = cv2.adaptiveThreshold(
                gray, 255, cv2.ADAPTIVE_THRESH_GAUSSIAN_C, cv2.THRESH_BINARY, 11, 2
            )

            # Fast non-local means denoising — reduces scanner noise
            denoised = cv2.fastNlMeansDenoising(gray, None, 10, 7, 21)

            # Sharpening kernel — improves soft / slightly blurred scans
            kernel = np.array([[-1, -1, -1], [-1, 9, -1], [-1, -1, -1]])
            sharpened = cv2.filter2D(gray, -1, kernel)

            # 2× upscale — helps OCR on small/low-res images.
            # Skip when the result would exceed _MAX_OCR_SIDE: the image is
            # already high-resolution enough and doubling would needlessly
            # create a large array that _resize_for_ocr would shrink back down.
            if max(gray.shape[:2]) * 2 <= self._MAX_OCR_SIDE:
                upscaled = cv2.resize(
                    gray, None, fx=2.0, fy=2.0, interpolation=cv2.INTER_CUBIC
                )
                variants.append(upscaled)

            # PaddleOCR accepts numpy arrays directly — no PIL conversion needed
            variants.extend([otsu, adaptive, denoised, sharpened])

        except Exception as e:
            logger.warning("cv2 preprocessing failed — using raw image only: %s", e)

        return variants


class ImageParser(PDFParser):
    """
    OCR parser for standalone image files (JPG/PNG/BMP/TIFF/WEBP).
    Reuses the same PaddleOCR + preprocessing pipeline as PDFParser.
    """

    def parse(self, file_path: str) -> Dict[str, Any]:
        import cv2

        img_np = cv2.imread(file_path)
        if img_np is None:
            raise ValueError(f"Unable to read image file '{file_path}'. File may be unreadable or corrupt.")

        text = self._extract_text_from_image_array(img_np, page_num=0)
        return {
            "data": [{"content": text}],
            "metadata": {
                "columns": ["content"],
                "rows": 1,
                "parser": "image_paddleocr",
            },
        }

    def parse_with_boxes(self, file_path: str) -> Dict[str, Any]:
        """
        Like parse() but also returns per-line bounding boxes on the original image.

        Two separate OCR passes are made deliberately:
          1. Multi-variant pass (_extract_text_from_image_array) — uses preprocessing
             pipelines (grayscale, Otsu, adaptive threshold, upscale …) to produce
             the highest-quality text for PII detection.
          2. Raw-image pass (_run_paddle_ocr_with_boxes) — runs on the unmodified
             original so that bbox pixel coordinates map directly to the stored image
             for redaction without any coordinate scaling.

        PII matching against boxes is done by value search (not char-span) in
        process_image_content, so the two passes don't need to be character-aligned.
        """
        import cv2

        img_np = cv2.imread(file_path)
        if img_np is None:
            raise ValueError(f"Unable to read image file '{file_path}'.")

        # Pass 1: best quality text (preprocessing variants)
        best_text = self._extract_text_from_image_array(img_np, page_num=0)

        # Pass 2: raw image for accurate bbox coords
        _, lines = self._run_paddle_ocr_with_boxes(img_np, page_num=0)

        return {
            "data": [{"content": best_text}],
            "lines": lines,
            "metadata": {
                "columns": ["content"],
                "rows": 1,
                "parser": "image_paddleocr",
            },
        }
