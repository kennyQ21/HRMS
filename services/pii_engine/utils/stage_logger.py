"""
Stage Logging Decorator

Decorator for logging pipeline stages with timing, input/output counts,
and error tracking. Works for both sync and async functions.

Usage:
    from services.pii_engine.utils.logger import get_logger
    from services.pii_engine.utils.stage_logger import log_stage
    
    logger = get_logger("pii_engine.parser")
    
    @log_stage(logger, "PARSER")
    def parse_file(file_path: str) -> dict:
        # ... parsing logic ...
        return {"text": "..."}
    
    @log_stage(logger, "OCR")
    async def run_ocr(image_path: str) -> str:
        # ... OCR logic ...
        return "..."
"""

from __future__ import annotations

import asyncio
import functools
import inspect
import time
from typing import Callable, TypeVar, Any
import logging

T = TypeVar("T")


def log_stage(logger: logging.Logger, stage_name: str):
    """
    Decorator for logging pipeline stages with timing and error tracking.
    
    Automatically logs:
    - Stage start with input parameters
    - Stage success with duration and output count
    - Stage failure with error details
    
    Args:
        logger: Logger instance to use
        stage_name: Name of the stage (e.g., "PARSER", "OCR", "NER")
    
    Returns:
        Decorated function with stage logging
    
    Example:
        @log_stage(logger, "PARSER")
        def parse_file(file_path: str) -> dict:
            return {"text": "..."}
        
        @log_stage(logger, "OCR")
        async def run_ocr(image_path: str) -> str:
            return "..."
    """
    def decorator(func: Callable[..., T]) -> Callable[..., T]:
        # Check if function is async
        is_async = asyncio.iscoroutinefunction(func)
        
        @functools.wraps(func)
        async def async_wrapper(*args, **kwargs) -> T:
            start_time = time.time()
            
            # Extract context info from arguments
            context = _extract_context(func, args, kwargs)
            context_str = " | ".join(f"{k}={v}" for k, v in context.items())
            
            logger.info(f"[{stage_name}] START | {func.__name__} | {context_str}" if context_str else f"[{stage_name}] START | {func.__name__}")
            
            try:
                result = await func(*args, **kwargs)
                duration_ms = (time.time() - start_time) * 1000
                
                # Extract output metrics
                output_context = _extract_output_metrics(result)
                output_str = " | ".join(f"{k}={v}" for k, v in output_context.items())
                
                logger.info(
                    f"[{stage_name}] SUCCESS | {func.__name__} | {duration_ms:.2f}ms" +
                    (f" | {output_str}" if output_str else "")
                )
                return result
                
            except Exception as e:
                duration_ms = (time.time() - start_time) * 1000
                logger.error(
                    f"[{stage_name}] FAILED | {func.__name__} | {duration_ms:.2f}ms | error={type(e).__name__}: {e}",
                    extra={"stage": stage_name, "duration_ms": duration_ms, "error": str(e)},
                    exc_info=True
                )
                raise
        
        @functools.wraps(func)
        def sync_wrapper(*args, **kwargs) -> T:
            start_time = time.time()
            
            # Extract context info from arguments
            context = _extract_context(func, args, kwargs)
            context_str = " | ".join(f"{k}={v}" for k, v in context.items())
            
            logger.info(f"[{stage_name}] START | {func.__name__}" + (f" | {context_str}" if context_str else ""))
            
            try:
                result = func(*args, **kwargs)
                duration_ms = (time.time() - start_time) * 1000
                
                # Extract output metrics
                output_context = _extract_output_metrics(result)
                output_str = " | ".join(f"{k}={v}" for k, v in output_context.items())
                
                logger.info(
                    f"[{stage_name}] SUCCESS | {func.__name__} | {duration_ms:.2f}ms" +
                    (f" | {output_str}" if output_str else "")
                )
                return result
                
            except Exception as e:
                duration_ms = (time.time() - start_time) * 1000
                logger.error(
                    f"[{stage_name}] FAILED | {func.__name__} | {duration_ms:.2f}ms | error={type(e).__name__}: {e}",
                    extra={"stage": stage_name, "duration_ms": duration_ms, "error": str(e)},
                    exc_info=True
                )
                raise
        
        return async_wrapper if is_async else sync_wrapper
    
    return decorator


def _extract_context(func: Callable, args: tuple, kwargs: dict) -> dict:
    """
    Extract context information from function arguments.
    
    Attempts to extract commonly useful context:
    - file_path from first argument if string and looks like path
    - Number of arguments
    - Keyword argument names (not values, for privacy)
    """
    context = {}
    
    # Try to get file_path from first argument
    if args and isinstance(args[0], str):
        arg = args[0]
        if "." in arg or "/" in arg or "\\" in arg:  # Looks like a file path
            import os
            context["file"] = os.path.basename(arg)
    
    # For dict arguments, get summary counts
    if args and isinstance(args[0], dict):
        context["input_keys"] = len(args[0])
    
    # For list arguments, get count
    if args and isinstance(args[0], (list, tuple)):
        context["input_count"] = len(args[0])
    
    return context


def _extract_output_metrics(result: Any) -> dict:
    """
    Extract metrics from function result.
    
    Attempts to extract useful counts and metrics:
    - Length of string result
    - Count of list/dict results
    - Specific metrics from result dict
    """
    metrics = {}
    
    if result is None:
        return metrics
    
    if isinstance(result, str):
        # Text extraction result
        metrics["chars"] = len(result)
        metrics["words"] = len(result.split())
    
    elif isinstance(result, dict):
        # Could be parser output or detection result
        if "text" in result:
            # Parser output with text
            text = result["text"]
            if isinstance(text, str):
                metrics["chars"] = len(text)
                metrics["words"] = len(text.split())
        
        if "data" in result:
            # Parser output with data list
            data = result["data"]
            if isinstance(data, list):
                metrics["rows"] = len(data)
                if data and isinstance(data[0], dict):
                    metrics["columns"] = len(data[0])
        
        if "entities" in result:
            # PII detection result
            entities = result["entities"]
            if isinstance(entities, list):
                metrics["entities"] = len(entities)
                # Count by type
                type_counts = {}
                for e in entities:
                    if isinstance(e, dict) and "type" in e:
                        etype = e["type"]
                        type_counts[etype] = type_counts.get(etype, 0) + 1
                if type_counts:
                    for etype, count in sorted(type_counts.items()):
                        metrics[f"count_{etype}"] = count
        
        if "metadata" in result:
            # Parser metadata
            metadata = result["metadata"]
            if isinstance(metadata, dict):
                if "parser" in metadata:
                    metrics["parser"] = metadata["parser"]
                if "pages" in metadata:
                    metrics["pages"] = metadata["pages"]
        
        if "lines" in result:
            # OCR result with lines
            lines = result["lines"]
            if isinstance(lines, list):
                metrics["lines"] = len(lines)
        
        if "matches" in result:
            # PII match result
            matches = result["matches"]
            if isinstance(matches, list):
                metrics["matches"] = len(matches)
        
        if "count" in result:
            metrics["count"] = result["count"]
        
        if "total" in result:
            metrics["total"] = result["total"]
    
    elif isinstance(result, (list, tuple)):
        metrics["count"] = len(result)
    
    return metrics