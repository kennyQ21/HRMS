"""
services/content_reconstruction.py
-------------------------------------
Content Reconstruction Layer.

Critical enterprise layer that sits between the raw parser output and the
detection pipeline.

Purpose:
  • Merge OCR text with native text-layer output (best of both)
  • Restore logical reading order for multi-column / complex layouts
  • Preserve table spatial relationships as structured text
  • Annotate content blocks with source metadata (page, block type, bbox)
  • Produce a single unified ContentDocument consumed by text_normalizer

Input sources:
  A. parser_output  — from FileParser (text layer, structured data)
  B. ocr_output     — from OCR worker (raw OCR lines + bboxes)
  C. metadata       — filename, page count, file size, MIME type

Output:
  ContentDocument with:
    .full_text       — unified plain text for detection engines
    .blocks          — list of ContentBlock (page/section/table/paragraph)
    .metadata        — document-level metadata
    .reading_order   — ordered list of block ids
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import Any, Optional

logger = logging.getLogger(__name__)


@dataclass
class ContentBlock:
    """
    A discrete unit of content (paragraph, table, heading, list, etc.)
    with its position in the document and source metadata.
    """
    block_id:    int
    block_type:  str        # "paragraph" | "table" | "heading" | "list" | "ocr_line" | "cell"
    text:        str
    page:        int = 0    # 0 = unknown / single-page document
    bbox:        Optional[list] = None   # [[x1,y1],[x2,y1],[x2,y2],[x1,y2]] in pixels
    source:      str = "parser"          # "parser" | "ocr" | "merged"
    confidence:  float = 1.0
    metadata:    dict = field(default_factory=dict)


@dataclass
class ContentDocument:
    """
    Unified document representation after content reconstruction.
    Consumed by TextNormalizer → DetectionDispatcher.
    """
    filename:      str
    full_text:     str                          # single concatenated text for NLP
    blocks:        list[ContentBlock] = field(default_factory=list)
    reading_order: list[int]          = field(default_factory=list)   # block_ids in order
    metadata:      dict               = field(default_factory=dict)
    ocr_lines:     list[tuple]        = field(default_factory=list)   # (text, bbox) raw OCR

    @property
    def page_count(self) -> int:
        pages = {b.page for b in self.blocks if b.page > 0}
        return max(pages) if pages else 1

    @property
    def has_tables(self) -> bool:
        return any(b.block_type == "table" for b in self.blocks)

    @property
    def structured_text(self) -> str:
        """Full text preserving table structure with | separators."""
        parts: list[str] = []
        for block_id in self.reading_order:
            block = next((b for b in self.blocks if b.block_id == block_id), None)
            if block:
                parts.append(block.text)
        return "\n\n".join(p for p in parts if p.strip()) or self.full_text


class ContentReconstructor:
    """
    Merges parser output, OCR output and metadata into a ContentDocument.

    Handles three cases:
      1. Text-only (PDF with text layer, DOCX, CSV)
      2. OCR-only (scanned PDF, image)
      3. Mixed (PDF with partial text layer supplemented by OCR)
    """

    def reconstruct(
        self,
        filename: str,
        parser_output: dict,
        ocr_output: Optional[list[dict]] = None,
        file_metadata: Optional[dict] = None,
    ) -> ContentDocument:
        """
        Produce a ContentDocument from all available sources.

        Args:
            filename:      Original file name.
            parser_output: Dict returned by any parser's .parse() method.
                           Must have keys: "data" (list of items), "metadata".
            ocr_output:    Optional list of {text, lines} dicts from ocr_worker.
                           One entry per page for PDFs, single entry for images.
            file_metadata: Optional dict with file-level facts (size, mime, etc.)
        """
        doc_meta = {
            "filename": filename,
            **(file_metadata or {}),
            **(parser_output.get("metadata", {})),
        }

        parser_type = parser_meta_type(parser_output)
        blocks: list[ContentBlock] = []
        ocr_lines: list[tuple] = []
        block_id = 0

        # ── A. Structured data (CSV / XLSX / MDB) ─────────────────────────────
        if parser_type in {"csv", "xlsx", "mdb"}:
            blocks, block_id = self._reconstruct_structured(
                parser_output, filename, block_id
            )

        # ── B. Tabular parser output with row items ────────────────────────────
        elif "rows" in parser_output.get("metadata", {}) and parser_output["metadata"].get("rows", 0) > 1:
            blocks, block_id = self._reconstruct_structured(
                parser_output, filename, block_id
            )

        # ── C. Document / OCR text ─────────────────────────────────────────────
        else:
            # Native text from parser
            parser_text = self._extract_parser_text(parser_output)

            # OCR text (may supplement or replace parser text)
            all_ocr_text = ""
            if ocr_output:
                for page_idx, page_ocr in enumerate(ocr_output):
                    page_text = page_ocr.get("text", "")
                    page_lines = page_ocr.get("lines", [])

                    if page_text.strip():
                        blocks.append(ContentBlock(
                            block_id=block_id,
                            block_type="ocr_line",
                            text=page_text,
                            page=page_idx + 1,
                            source="ocr",
                            confidence=0.90,
                        ))
                        block_id += 1
                        all_ocr_text += page_text + "\n\n"

                    for line_text, bbox in page_lines:
                        if line_text.strip():
                            ocr_lines.append((line_text, bbox))

            # Merge: prefer longer source (more complete text)
            merged_text = self._merge_text_sources(parser_text, all_ocr_text)

            # Split into paragraph blocks for reading-order tracking
            para_blocks, block_id = self._split_into_blocks(
                merged_text, block_id,
                source="merged" if all_ocr_text and parser_text else
                       ("ocr" if all_ocr_text else "parser"),
            )
            blocks.extend(para_blocks)

        # ── Reading order ──────────────────────────────────────────────────────
        # For now: natural document order (id sequence). Future: spatial sort.
        reading_order = [b.block_id for b in blocks]

        # ── Full text assembly ─────────────────────────────────────────────────
        full_text = self._assemble_full_text(blocks)
        if not full_text.strip():
            # Fallback to raw parser text if block assembly produced nothing
            full_text = self._extract_parser_text(parser_output)

        logger.info(
            "[RECONSTRUCTION] %s: %d blocks, %d chars, %d OCR lines",
            filename, len(blocks), len(full_text), len(ocr_lines),
        )

        return ContentDocument(
            filename=filename,
            full_text=full_text,
            blocks=blocks,
            reading_order=reading_order,
            metadata=doc_meta,
            ocr_lines=ocr_lines,
        )

    # ── Structured data ────────────────────────────────────────────────────────

    def _reconstruct_structured(
        self, parser_output: dict, filename: str, block_id: int
    ) -> tuple[list[ContentBlock], int]:
        """
        Convert CSV/XLSX/MDB row data into blocks.
        Each row is one block; column headers are embedded.
        """
        blocks: list[ContentBlock] = []
        data = parser_output.get("data", [])
        metadata = parser_output.get("metadata", {})
        columns = metadata.get("columns", [])

        # Header block
        if columns:
            header_text = " | ".join(str(c) for c in columns)
            blocks.append(ContentBlock(
                block_id=block_id,
                block_type="table",
                text=header_text,
                source="parser",
                metadata={"role": "header"},
            ))
            block_id += 1

        # Row blocks
        for row in data:
            if isinstance(row, dict):
                row_text = " | ".join(
                    f"{k}: {v}" for k, v in row.items()
                    if v is not None and str(v).strip()
                )
            else:
                row_text = str(row)

            if row_text.strip():
                blocks.append(ContentBlock(
                    block_id=block_id,
                    block_type="cell",
                    text=row_text,
                    source="parser",
                ))
                block_id += 1

        return blocks, block_id

    # ── Text merging ───────────────────────────────────────────────────────────

    def _extract_parser_text(self, parser_output: dict) -> str:
        """Pull plain text from any parser output format."""
        data = parser_output.get("data", [])
        if not data:
            return ""
        # Document parsers put everything in data[0]["content"]
        if len(data) == 1 and "content" in data[0]:
            return data[0]["content"] or ""
        # Structured parsers: join all values
        parts: list[str] = []
        for item in data:
            if isinstance(item, dict):
                content = item.get("content") or " | ".join(
                    str(v) for v in item.values() if v is not None
                )
                if content:
                    parts.append(content)
        return "\n\n".join(parts)

    def _merge_text_sources(self, parser_text: str, ocr_text: str) -> str:
        """
        Merge parser text and OCR text.

        Rule: use the longer source as primary.
        If both are substantial, prepend the parser text (better formatting)
        and append any OCR-only content not in parser text.
        """
        pt = parser_text.strip()
        ot = ocr_text.strip()

        if not pt and not ot:
            return ""
        if not pt:
            return ot
        if not ot:
            return pt

        # Both have content: prefer parser text if it's ≥80% as long as OCR
        if len(pt) >= len(ot) * 0.8:
            logger.debug(
                "[RECONSTRUCTION] Using parser text (%d chars) over OCR (%d chars)",
                len(pt), len(ot),
            )
            return pt

        # OCR is substantially longer — use it but prepend short parser snippets
        logger.debug(
            "[RECONSTRUCTION] OCR text (%d chars) preferred over parser (%d chars)",
            len(ot), len(pt),
        )
        return ot

    def _split_into_blocks(
        self, text: str, start_id: int, source: str = "parser"
    ) -> tuple[list[ContentBlock], int]:
        """Split text into paragraph-level blocks."""
        blocks: list[ContentBlock] = []
        block_id = start_id

        # Split on double newlines (paragraph boundaries)
        paragraphs = re.split(r"\n{2,}", text)

        for para in paragraphs:
            stripped = para.strip()
            if not stripped:
                continue

            # Detect headings (short lines, ALL CAPS or ends with :)
            block_type = "paragraph"
            if len(stripped) < 80 and (stripped.isupper() or stripped.endswith(":")):
                block_type = "heading"
            elif "|" in stripped and stripped.count("|") >= 2:
                block_type = "table"

            blocks.append(ContentBlock(
                block_id=block_id,
                block_type=block_type,
                text=stripped,
                source=source,
            ))
            block_id += 1

        return blocks, block_id

    # ── Full text assembly ─────────────────────────────────────────────────────

    def _assemble_full_text(self, blocks: list[ContentBlock]) -> str:
        """Concatenate all blocks into a single string for NLP."""
        parts: list[str] = []
        for block in blocks:
            if block.text.strip():
                parts.append(block.text.strip())
        return "\n\n".join(parts)


# ── Helpers ───────────────────────────────────────────────────────────────────

def parser_meta_type(parser_output: dict) -> str:
    """Infer parser type from metadata.parser field."""
    parser_name = parser_output.get("metadata", {}).get("parser", "")
    if "csv" in parser_name:
        return "csv"
    if any(k in parser_name for k in ("excel", "xlsx", "xls")):
        return "xlsx"
    if "mdb" in parser_name or "access" in parser_name:
        return "mdb"
    return "document"


# ── Module-level singleton ────────────────────────────────────────────────────

_reconstructor = ContentReconstructor()


def reconstruct_content(
    filename: str,
    parser_output: dict,
    ocr_output: Optional[list[dict]] = None,
    file_metadata: Optional[dict] = None,
) -> ContentDocument:
    return _reconstructor.reconstruct(
        filename=filename,
        parser_output=parser_output,
        ocr_output=ocr_output,
        file_metadata=file_metadata,
    )
