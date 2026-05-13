"""
services/pipeline_runner.py
----------------------------
Thin pipeline executor — calls stages in order, collects timings, handles failures.

NO business logic here.
NO detection logic here.
NO AI orchestration here.

Just: call stage → catch errors → record timing → continue.
"""

from __future__ import annotations

import logging
from typing import Optional

from services.pipeline_context import PipelineContext

logger = logging.getLogger(__name__)


class PipelineError(Exception):
    """Raised when a pipeline stage fails critically."""
    def __init__(self, stage: str, message: str):
        self.stage = stage
        super().__init__(f"[{stage}] {message}")


def run_pipeline(ctx: PipelineContext) -> PipelineContext:
    """
    Execute the full scan pipeline on a PipelineContext.

    Stages are called in order. Each stage reads/writes ctx.
    On non-critical failure: add warning, continue.
    On critical failure: raise PipelineError.
    """
    try:
        _stage_ingest(ctx)
        _stage_parse(ctx)
        _stage_normalize(ctx)
        _stage_detect(ctx)
        _stage_resolve(ctx)
        _stage_bbox_map(ctx)
        _stage_ocr_validate(ctx)
        _stage_post_process(ctx)
        _stage_validate(ctx)

    except PipelineError as exc:
        ctx.add_warning(str(exc))
        logger.error("Pipeline failed at %s: %s", exc.stage, exc)
        raise

    except Exception as exc:
        ctx.add_warning("unhandled_error: " + str(exc))
        logger.exception("Unhandled pipeline error")
        raise

    finally:
        ctx.finalize()

    return ctx


# ── Stage implementations ────────────────────────────────────────────────────

def _stage_ingest(ctx: PipelineContext) -> None:
    """1. Ingestion routing — determine parser and document profile."""
    from services.ingestion_dispatcher import dispatch_ingestion

    plan = dispatch_ingestion(ctx.file_path, ctx.filename, ctx.password)
    ctx.ingestion_plan = plan
    ctx.document_profile = plan.document_profile

    if plan.parser_type == "unknown":
        raise PipelineError("ingest", "Unsupported file format")

    ctx.mark_stage("ingest")


def _stage_parse(ctx: PipelineContext) -> None:
    """2. Parse file — extract text, OCR if needed."""
    from routers.scan import _get_parser
    from services.pipeline_context import ContentDocument

    parser = _get_parser(ctx.filename, ctx.password)
    if parser is None:
        raise PipelineError("parse", "No parser available for this format")

    ctx.is_image = ctx.filename.lower().endswith(
        (".jpg", ".jpeg", ".png", ".bmp", ".tif", ".tiff", ".webp")
    )

    if ctx.is_image:
        parsed_data = parser.parse_with_boxes(ctx.file_path)
        ocr_output = [{
            "text": parsed_data["data"][0].get("content", ""),
            "lines": parsed_data.get("lines", []),
        }]
    else:
        parsed_data = parser.parse(ctx.file_path)
        ocr_output = None

    if not parser.validate(parsed_data):
        raise PipelineError("parse", "Invalid file structure")

    # Build ContentDocument
    from services.content_reconstruction import reconstruct_content
    content_doc = reconstruct_content(
        filename=ctx.filename,
        parser_output=parsed_data,
        ocr_output=ocr_output,
        file_metadata={"doc_type": ctx.ingestion_plan.parser_type},
    )

    ctx.parsed_data = parsed_data
    ctx.content_document = ContentDocument(
        full_text=content_doc.full_text or "",
        blocks=content_doc.blocks if hasattr(content_doc, "blocks") else [],
        page_count=content_doc.page_count if hasattr(content_doc, "page_count") else 1,
        ocr_output=ocr_output,
    )

    ctx.mark_stage("parse")


def _stage_normalize(ctx: PipelineContext) -> None:
    """3. OCR normalization — clean artifacts, establish canonical text.

    ALL spans in the pipeline refer to normalised text coordinates.
    The NormalisedText object provides to_original_span() for converting
    back to raw coordinates ONLY at redaction/display time.
    """
    from services.ocr_normalizer import clean_ocr
    from services.text_normalizer import NormalisedText, normalise

    raw_text = ctx.content_document.full_text or ""
    if not raw_text and ctx.parsed_data and ctx.parsed_data.get("data"):
        raw_text = ctx.parsed_data["data"][0].get("content", "")

    # First clean OCR artifacts, then apply full Unicode normalization
    cleaned = clean_ocr(raw_text)
    norm_result = normalise(cleaned)

    ctx.normalized_text = norm_result

    ctx.mark_stage("normalize")


def _stage_detect(ctx: PipelineContext) -> None:
    """4. Language detection + script-aware engine routing."""
    from services.detection_dispatcher import dispatch_detection
    from services.pipeline_context import EngineResult

    working_text = ctx.normalized_text.normalised

    result = dispatch_detection(
        text=working_text,
        doc_type=ctx.ingestion_plan.parser_type,
    )

    ctx.language_result = result.language
    ctx.resolved_entities = result.resolved
    ctx.engine_results = [
        EngineResult(
            engine=e.engine,
            matches=e.matches,
            elapsed_ms=getattr(e, "duration_ms", getattr(e, "elapsed_ms", 0)),
            error=getattr(e, "error", None),
        )
        for e in result.engine_results
    ]

    # Store normalised text from dispatcher (may differ from our normalization)
    if result.normalised_text:
        ctx.normalized_text.normalised = result.normalised_text.normalised

    # Record engine timings
    for er in ctx.engine_results:
        ctx.metrics.engine_timings.append({
            "engine": er.engine,
            "matches": len(er.matches),
            "ms": er.elapsed_ms,
        })
        if er.error == "timeout":
            ctx.metrics.timeouts += 1
            ctx.add_warning(f"{er.engine}_timeout")

    # Record language info
    if ctx.language_result:
        ctx.metrics.language = ctx.language_result.primary_lang
        ctx.metrics.dominant_script = getattr(
            ctx.language_result, "dominant_script", "latin"
        )

    ctx.mark_stage("detect")


def _stage_resolve(ctx: PipelineContext) -> None:
    """5. Entity resolution is already done inside detection_dispatcher.
    This stage is a no-op placeholder for future separation."""
    ctx.mark_stage("resolve")


def _stage_bbox_map(ctx: PipelineContext) -> None:
    """6. Map semantic entity spans to OCR bounding boxes (images only)."""
    if ctx.is_image and ctx.content_document.ocr_output:
        from services.bbox_mapper import map_entities_to_bboxes

        ocr_lines = []
        for ocr_page in (ctx.content_document.ocr_output or []):
            ocr_lines.extend(ocr_page.get("lines", []))

        ctx.resolved_entities = map_entities_to_bboxes(
            ctx.resolved_entities, ocr_lines, ctx.normalized_text.normalised
        )

    ctx.mark_stage("bbox_map")


def _stage_ocr_validate(ctx: PipelineContext) -> None:
    """7. Validate OCR ↔ entity ↔ bbox alignment (images only)."""
    if ctx.is_image and ctx.content_document.ocr_output:
        from services.ocr_validator import validate_ocr_alignment

        ocr_lines = []
        ocr_quality = None
        for ocr_page in (ctx.content_document.ocr_output or []):
            ocr_lines.extend(ocr_page.get("lines", []))
            if "ocr_quality" in ocr_page:
                ocr_quality = ocr_page["ocr_quality"]

        report = validate_ocr_alignment(
            entities=ctx.resolved_entities,
            ocr_lines=ocr_lines,
            ocr_quality=ocr_quality,
        )

        if not report.passed:
            for issue in report.issues:
                ctx.add_warning(f"ocr_validation: {issue}")

        if report.manual_review_required:
            ctx.add_warning("manual_review_required: low OCR confidence")

        # Store report in context metadata
        ctx.validation_report_ocr = report

    ctx.mark_stage("ocr_validate")


def _stage_post_process(ctx: PipelineContext) -> None:
    """7. Precision filter + entity count protection."""
    from services.post_processor import post_process

    resolved_raw = ctx.resolved_entities
    resolved = post_process(resolved_raw)

    # Entity count protection — never silently discard
    MAX_ENTITY_COUNT = 500
    if len(resolved) > MAX_ENTITY_COUNT:
        ctx.add_warning(
            "entity_limit_exceeded: %d entities found, keeping top %d by confidence"
            % (len(resolved), MAX_ENTITY_COUNT)
        )
        ctx.partial_scan = True
        resolved.sort(key=lambda e: e.confidence, reverse=True)
        resolved = resolved[:MAX_ENTITY_COUNT]

    ctx.resolved_entities = resolved
    ctx.mark_stage("post_process")


def _stage_validate(ctx: PipelineContext) -> None:
    """8. Span integrity validation."""
    from services.validator import validate_results
    from services.pipeline_context import ValidationReport

    text = ctx.normalized_text.normalised
    validation = validate_results(text=text, resolved_entities=ctx.resolved_entities)

    ctx.validation_report = ValidationReport(
        passed=validation.passed,
        issues=validation.issues if hasattr(validation, "issues") else [],
        span_errors=validation.span_errors if hasattr(validation, "span_errors") else 0,
    )

    ctx.mark_stage("validate")
