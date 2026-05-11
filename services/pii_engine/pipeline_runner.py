"""
Comprehensive Pipeline Runner with Observability

Orchestrates the full PII detection pipeline with:
- Structured logging for every stage
- Timing and metrics tracking
- Debug output dumps
- Performance metrics
- Error handling and recovery

Usage:
    from services.pii_engine.pipeline_runner import run_pipeline
    
    result = await run_pipeline(
        file_path="document.pdf",
        debug=True
    )
    
    print(result["timing"]["total_seconds"])
    print(result["entities"])
"""

from __future__ import annotations

import os
import time
from typing import Any, Dict, List, Optional, Callable
from dataclasses import dataclass, field
import logging

from .utils.logger import (
    get_logger,
    setup_logger,
    log_separator,
    log_stage_start,
    log_stage_success,
    log_stage_failure,
    log_metrics,
    log_warning,
)
from .utils.debug_dumper import DebugDumper, get_request_dumper
from .core.pipeline_context import PipelineContext, StageMetrics
from .validation.output_validator import validate_output, format_validation_errors

# Import existing services
from services.pii_service import detect_pii, PIIResult, PIIMatch

# Try importing parsers (graceful fallback)
try:
    from parsers.base import BaseParser
    from parsers.unstructured.document_parser import DocumentParser, PDFParser, ImageParser
    from parsers.structured.csv_parser import CSVParser
    from parsers.structured.excel_parser import ExcelParser
    from parsers.unstructured.access_parser import MDBParser
    from parsers.unstructured.sql_parser import SQLParser
    PARSERS_AVAILABLE = True
except ImportError:
    PARSERS_AVAILABLE = False
    BaseParser = None
    DocumentParser = PDFParser = ImageParser = None
    CSVParser = ExcelParser = None
    MDBParser = SQLParser = None


# Configure logger
logger = setup_logger("pii_engine.pipeline")


# ─────────────────────────────────────────────────────────────────────────────
# Parser Registry
# ─────────────────────────────────────────────────────────────────────────────

PARSER_REGISTRY: Dict[str, Callable[[], BaseParser]] = {
    # Documents
    "pdf": lambda: PDFParser(),
    "docx": lambda: DocumentParser(),
    "doc": lambda: DocumentParser(),
    "odt": lambda: DocumentParser(),
    "rtf": lambda: DocumentParser(),
    # Images
    "jpg": lambda: ImageParser(),
    "jpeg": lambda: ImageParser(),
    "png": lambda: ImageParser(),
    "bmp": lambda: ImageParser(),
    "tif": lambda: ImageParser(),
    "tiff": lambda: ImageParser(),
    "webp": lambda: ImageParser(),
    # Structured
    "csv": lambda: CSVParser(),
    "xlsx": lambda: ExcelParser(),
    "xls": lambda: ExcelParser(),
    "mdb": lambda: MDBParser(),
    "sql": lambda: SQLParser(),
}


def get_parser_for_file(filename: str, password: Optional[str] = None) -> Optional[BaseParser]:
    """
    Get the appropriate parser for a file based on extension.
    
    Args:
        filename: File name or path
        password: Optional password for encrypted files
    
    Returns:
        Parser instance or None if unsupported
    """
    ext = filename.lower().rsplit(".", 1)[-1] if "." in filename else ""
    
    # Special case for PDF with password
    if ext == "pdf" and password:
        return PDFParser(password=password)
    
    if ext in PARSER_REGISTRY:
        return PARSER_REGISTRY[ext]()
    
    return None


def get_supported_extensions() -> List[str]:
    """Get list of supported file extensions."""
    return list(PARSER_REGISTRY.keys())


# ─────────────────────────────────────────────────────────────────────────────
# Pipeline Stage Functions
# ─────────────────────────────────────────────────────────────────────────────

def extract_text(
    parser: BaseParser,
    file_path: str,
    ctx: PipelineContext,
    dumper: DebugDumper,
    logger: logging.Logger,
) -> Dict[str, Any]:
    """
    Extract text from file using parser.
    
    Returns:
        Parser result with text content and metadata
    """
    with ctx.track_stage("parser") as stage:
        logger.info(f"[UPLOAD] file={os.path.basename(file_path)}")
        
        parser_name = parser.__class__.__name__
        stage.add_metadata("parser", parser_name)
        
        logger.info(f"[PARSER] Selected: {parser_name}")
        
        try:
            result = parser.parse(file_path)
            
            # Get text content
            text = ""
            if result and "data" in result:
                if isinstance(result["data"], list) and result["data"]:
                    text = result["data"][0].get("content", "")
            
            # Calculate metrics
            char_count = len(text)
            word_count = len(text.split()) if text else 0
            
            stage.set_output(char_count, words=word_count)
            
            logger.info(f"[TEXT] chars={char_count} words={word_count}")
            
            # Dump raw text for debugging
            dumper.dump_raw_text(text, os.path.basename(file_path))
            
            return {
                "text": text,
                "metadata": result.get("metadata", {}),
                "parser_name": parser_name,
            }
            
        except Exception as e:
            logger.error(f"[PARSER] FAILED: {e}")
            raise


def detect_language(text: str, ctx: PipelineContext, logger: logging.Logger) -> str:
    """
    Detect language of text (basic heuristic).
    
    Returns:
        Language code (en, etc.)
    """
    with ctx.track_stage("language") as stage:
        # Simple heuristic - could be enhanced with langdetect
        lang = "en"  # Default to English
        
        # Check for common non-English patterns
        devanagari_chars = sum(1 for c in text if '\u0900' <= c <= '\u097F')
        if devanagari_chars > len(text) * 0.2:
            lang = "hi"  # Hindi
        
        stage.add_metadata("language", lang)
        logger.info(f"[LANG] Detected: {lang}")
        
        return lang


def run_ocr_fallback(
    file_path: str,
    ctx: PipelineContext,
    dumper: DebugDumper,
    logger: logging.Logger,
) -> str:
    """
    Run OCR for scanned documents.
    
    Returns:
        OCR text
    """
    with ctx.track_stage("ocr") as stage:
        logger.warning(f"[OCR] Fallback triggered for {os.path.basename(file_path)}")
        
        parser = ImageParser()
        result = parser.parse(file_path)
        
        text = result["data"][0].get("content", "") if result and result.get("data") else ""
        
        stage.set_output(len(text))
        logger.info(f"[OCR] chars={len(text)}")
        
        # Dump OCR text for debugging
        dumper.dump_ocr_text(text, os.path.basename(file_path))
        
        return text


def detect_pii_regex(
    text: str,
    ctx: PipelineContext,
    dumper: DebugDumper,
    logger: logging.Logger,
    source_file: str,
) -> List[PIIMatch]:
    """
    Run regex-based PII detection.
    
    Returns:
        List of PIIMatch objects
    """
    with ctx.track_stage("regex") as stage:
        stage.set_input(len(text))
        
        # Use regex-only detection (fast)
        result = detect_pii(text, use_nlp=False)
        matches = result.matches
        
        stage.set_output(len(matches))
        
        logger.info(f"[REGEX] matches={len(matches)}")
        
        # Dump regex matches
        dumper.dump_regex_matches(
            [{"type": m.pii_type, "value": m.value, "confidence": m.confidence} for m in matches],
            source_file
        )
        
        return matches


def detect_pii_ner(
    text: str,
    ctx: PipelineContext,
    dumper: DebugDumper,
    logger: logging.Logger,
    source_file: str,
) -> List[PIIMatch]:
    """
    Run NER-based PII detection (Presidio).
    
    Returns:
        List of PIIMatch objects
    """
    with ctx.track_stage("ner") as stage:
        stage.set_input(len(text))
        
        # Use full hybrid detection (regex + Presidio)
        result = detect_pii(text, use_nlp=True)
        matches = [m for m in result.matches if m.source == "presidio"]
        
        stage.set_output(len(matches))
        
        logger.info(f"[NER] entities={len(matches)}")
        
        # Dump NER entities
        dumper.dump_ner_entities(
            [{"type": m.pii_type, "value": m.value, "confidence": m.confidence} for m in matches],
            source_file
        )
        
        return matches


def resolve_entities(
    regex_matches: List[PIIMatch],
    ner_matches: List[PIIMatch],
    ctx: PipelineContext,
    dumper: DebugDumper,
    logger: logging.Logger,
    source_file: str,
) -> List[Dict]:
    """
    Merge and deduplicate entities from multiple sources.
    
    Returns:
        List of merged entities
    """
    with ctx.track_stage("resolution") as stage:
        stage.set_input(len(regex_matches) + len(ner_matches))
        
        # Merge matches
        all_matches = list(regex_matches) + list(ner_matches)
        
        # Convert to output format
        entities = []
        seen = set()
        
        for match in all_matches:
            # Deduplicate by (type, value)
            key = (match.pii_type, match.value.lower().strip())
            if key in seen:
                continue
            seen.add(key)
            
            entities.append({
                "type": match.pii_type.upper(),
                "value": match.value,
                "start": match.start,
                "end": match.end,
                "confidence": match.confidence,
                "source": match.source,
            })
        
        stage.set_output(len(entities))
        
        logger.info(f"[RESOLUTION] merged={len(entities)} (from {len(regex_matches)} regex + {len(ner_matches)} ner)")
        
        # Dump merged entities
        dumper.dump_merged_entities(
            [{"type": m.pii_type, "value": m.value} for m in regex_matches],
            [{"type": m.pii_type, "value": m.value} for m in ner_matches],
            entities,
            source_file
        )
        
        return entities


def validate_output_schema(
    output: Dict,
    ctx: PipelineContext,
    logger: logging.Logger,
) -> bool:
    """
    Validate output JSON schema.
    
    Returns:
        True if valid, False otherwise
    """
    with ctx.track_stage("validation") as stage:
        result = validate_output(output, strict=False)
        
        if not result.valid:
            logger.error(f"[VALIDATION] FAILED: {len(result.errors)} errors, {len(result.warnings)} warnings")
            for error in result.errors[:5]:  # Show first 5
                logger.error(f"  - {error}")
        else:
            logger.info(f"[VALIDATION] schema=PASS")
            if result.warnings:
                logger.warning(f"[VALIDATION] {len(result.warnings)} warnings")
        
        stage.add_metadata("valid", result.valid)
        stage.add_metadata("error_count", len(result.errors))
        stage.add_metadata("warning_count", len(result.warnings))
        
        return result.valid


def save_output(
    output: Dict,
    ctx: PipelineContext,
    dumper: DebugDumper,
    logger: logging.Logger,
    output_dir: Optional[str] = None,
) -> str:
    """
    Save final output to JSON file.
    
    Returns:
        Path to output file
    """
    import json
    from datetime import datetime
    
    with ctx.track_stage("output") as stage:
        if output_dir is None:
            output_dir = "results"
        
        os.makedirs(output_dir, exist_ok=True)
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        request_id = ctx.request_id
        output_path = os.path.join(output_dir, f"output_{request_id}_{timestamp}.json")
        
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(output, f, indent=2, ensure_ascii=False, default=str)
        
        stage.add_metadata("output_path", output_path)
        logger.info(f"[OUTPUT] saved={output_path}")
        
        # Also dump to debug directory
        dumper.dump_output_json(output, "final")
        
        return output_path


# ─────────────────────────────────────────────────────────────────────────────
# Main Pipeline Runner
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class PipelineResult:
    """Result of running the pipeline."""
    
    success: bool
    entities: List[Dict]
    metadata: Dict[str, Any]
    timing: Dict[str, float]
    context: PipelineContext
    output_path: Optional[str] = None
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)


def run_pipeline(
    file_path: str,
    password: Optional[str] = None,
    use_nlp: bool = True,
    debug: bool = False,
    output_dir: Optional[str] = None,
) -> PipelineResult:
    """
    Run the complete PII detection pipeline with full observability.
    
    Args:
        file_path: Path to file to process
        password: Optional password for encrypted files
        use_nlp: Whether to use NLP detection (Presidio)
        debug: Enable debug mode with intermediate dumps
        output_dir: Directory for output files
    
    Returns:
        PipelineResult with entities, timing, and metadata
    """
    # Initialize context and debug dumper
    ctx = PipelineContext(
        debug_mode=debug,
        debug_dir=f"debug/{os.path.basename(file_path).rsplit('.', 1)[0]}" if debug else None
    )
    dumper = DebugDumper(debug_dir=ctx.debug_dir or "debug", enabled=debug)
    
    # Initialize logger with request context
    pipeline_logger = setup_logger("pii_engine.pipeline")
    
    # Track timing
    start_time = time.time()
    errors: List[str] = []
    warnings: List[str] = []
    
    log_separator(pipeline_logger)
    pipeline_logger.info(f"[PIPELINE START] request_id={ctx.request_id} file={os.path.basename(file_path)}")
    
    try:
        # Stage 1: Get parser
        parser = get_parser_for_file(file_path, password)
        if parser is None:
            raise ValueError(f"Unsupported file format: {os.path.basename(file_path)}")
        
        ctx.set_file_metadata(
            filename=os.path.basename(file_path),
            content_type=f"application/{file_path.rsplit('.', 1)[-1]}",
            size_bytes=os.path.getsize(file_path)
        )
        
        # Stage 2: Parse file
        parse_result = extract_text(parser, file_path, ctx, dumper, pipeline_logger)
        text = parse_result["text"]
        parser_name = parse_result["parser_name"]
        
        # Check for empty text - try OCR fallback
        if not text or len(text.strip()) < 100:
            pipeline_logger.warning(f"[TEXT] Sparse (<100 chars) — checking for OCR fallback")
            # For PDF and images, OCR may have already been triggered
            # Additional OCR handling can be added here
            
        # Stage 3: Detect language
        language = detect_language(text, ctx, pipeline_logger)
        
        # Stage 4: Regex detection
        regex_matches = detect_pii_regex(text, ctx, dumper, pipeline_logger, os.path.basename(file_path))
        
        # Stage 5: NER detection (optional)
        ner_matches = []
        if use_nlp and len(text.split()) > 20:  # Only run NLP on substantial text
            ner_matches = detect_pii_ner(text, ctx, dumper, pipeline_logger, os.path.basename(file_path))
        
        # Stage 6: Resolve/merge entities
        entities = resolve_entities(
            regex_matches, ner_matches,
            ctx, dumper, pipeline_logger,
            os.path.basename(file_path)
        )
        
        # Build output
        output = {
            "request_id": ctx.request_id,
            "source_file": os.path.basename(file_path),
            "parser": parser_name,
            "text_length": len(text),
            "language": language,
            "entities": entities,
            "counts": {},
            "metadata": {
                "parser": parser_name,
                "text_length": len(text),
                "language": language,
                "use_nlp": use_nlp,
                "debug_mode": debug,
            },
            "timing": {},
        }
        
        # Calculate counts
        for entity in entities:
            etype = entity.get("type", "UNKNOWN")
            output["counts"][etype] = output["counts"].get(etype, 0) + 1
        
        # Stage 7: Validate output
        is_valid = validate_output_schema(output, ctx, pipeline_logger)
        if not is_valid:
            warnings.append("Output validation failed")
        
        # Stage 8: Save output
        output_path = save_output(output, ctx, dumper, pipeline_logger, output_dir)
        
        # Finalize context
        ctx.finalize()
        
        # Build timing report
        total_elapsed = time.time() - start_time
        timing = {
            "total_seconds": round(total_elapsed, 3),
            "total_ms": round(total_elapsed * 1000, 2),
            "stages": ctx.get_timing_summary(),
        }
        output["timing"] = timing
        
        # Log completion
        log_separator(pipeline_logger)
        pipeline_logger.info(
            f"[PIPELINE COMPLETE] request_id={ctx.request_id} "
            f"entities={len(entities)} "
            f"elapsed={total_elapsed:.2f}s"
        )
        log_separator(pipeline_logger)
        
        # Create debug summary if enabled
        if debug:
            dumper.create_summary(
                os.path.basename(file_path),
                **{
                    "request_id": ctx.request_id,
                    "parser": parser_name,
                    "text_length": len(text),
                    "entity_count": len(entities),
                    "regex_count": len(regex_matches),
                    "ner_count": len(ner_matches),
                    "elapsed_seconds": total_elapsed,
                }
            )
        
        return PipelineResult(
            success=True,
            entities=entities,
            metadata=output["metadata"],
            timing=timing,
            context=ctx,
            output_path=output_path,
            errors=errors,
            warnings=warnings,
        )
        
    except Exception as e:
        ctx.record_error("pipeline", e)
        ctx.finalize()
        
        elapsed = time.time() - start_time
        pipeline_logger.error(
            f"[PIPELINE FAILED] request_id={ctx.request_id} "
            f"elapsed={elapsed:.2f}s error={type(e).__name__}: {e}"
        )
        
        return PipelineResult(
            success=False,
            entities=[],
            metadata={},
            timing={"total_seconds": elapsed, "total_ms": elapsed * 1000},
            context=ctx,
            errors=[f"{type(e).__name__}: {str(e)}"],
            warnings=warnings,
        )


def run_pipeline_batch(
    file_paths: List[str],
    password: Optional[str] = None,
    use_nlp: bool = True,
    debug: bool = False,
    output_dir: Optional[str] = None,
) -> List[PipelineResult]:
    """
    Run the pipeline on multiple files.
    
    Args:
        file_paths: List of file paths to process
        password: Optional password for encrypted files
        use_nlp: Whether to use NLP detection
        debug: Enable debug mode
        output_dir: Directory for output files
    
    Returns:
        List of PipelineResult objects
    """
    results = []
    
    for file_path in file_paths:
        result = run_pipeline(
            file_path=file_path,
            password=password,
            use_nlp=use_nlp,
            debug=debug,
            output_dir=output_dir,
        )
        results.append(result)
    
    return results


# ─────────────────────────────────────────────────────────────────────────────
# Performance Metrics
# ─────────────────────────────────────────────────────────────────────────────

def get_pipeline_metrics(result: PipelineResult) -> Dict[str, Any]:
    """
    Extract performance and quality metrics from pipeline result.
    
    Returns:
        Dictionary with timing, throughput, and quality metrics
    """
    metrics = {
        "timing": result.timing,
        "entity_count": len(result.entities),
        "entity_breakdown": {},
        "throughput": {
            "entities_per_second": 0,
            "chars_per_second": 0,
        },
        "success": result.success,
        "error_count": len(result.errors),
        "warning_count": len(result.warnings),
    }
    
    # Entity breakdown by type
    for entity in result.entities:
        etype = entity.get("type", "UNKNOWN")
        metrics["entity_breakdown"][etype] = metrics["entity_breakdown"].get(etype, 0) + 1
    
    # Calculate throughput
    text_length = result.metadata.get("text_length", 0)
    total_seconds = result.timing.get("total_seconds", 0)
    
    if total_seconds > 0:
        metrics["throughput"]["entities_per_second"] = len(result.entities) / total_seconds
        metrics["throughput"]["chars_per_second"] = text_length / total_seconds
    
    return metrics