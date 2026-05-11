"""
Structured Logging Layer for PII Engine

Enterprise-grade logging with stage markers, timing, and context tracking.
Designed for production debugging of multi-stage pipelines.

Usage:
    from services.pii_engine.utils.logger import setup_logger, get_logger
    
    logger = setup_logger("pii_engine.parser")
    logger.info("[PARSER] Selected PDF parser")
    logger.info("[OCR] Text extraction empty -> OCR fallback")

Output format:
    2025-01-05 10:30:45.123 | INFO     | pii_engine.parser | [PARSER] Selected PDF parser
"""

from __future__ import annotations

import logging
import sys
from datetime import datetime
from typing import Optional
import json


# Log format with timestamp, level, logger name, and message
LOG_FORMAT = (
    "%(asctime)s | %(levelname)-8s | %(name)s | %(message)s"
)

# Date format for timestamps
DATE_FORMAT = "%Y-%m-%d %H:%M:%S"

# Global registry of loggers
_LOGGERS: dict[str, logging.Logger] = {}


def setup_logger(
    name: str,
    level: int = logging.INFO,
    log_file: Optional[str] = None,
    json_format: bool = False,
) -> logging.Logger:
    """
    Set up a structured logger with console and optional file output.
    
    Args:
        name: Logger name (typically module name like 'pii_engine.parser')
        level: Log level (default: INFO)
        log_file: Optional file path for persistent logging
        json_format: If True, output logs as JSON for log aggregation systems
    
    Returns:
        Configured logger instance
    """
    if name in _LOGGERS:
        return _LOGGERS[name]
    
    logger = logging.getLogger(name)
    
    # Avoid duplicate handlers on reconfiguration
    if logger.handlers:
        _LOGGERS[name] = logger
        return logger
    
    logger.setLevel(level)
    
    # Console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(level)
    
    if json_format:
        formatter = JsonFormatter()
    else:
        formatter = logging.Formatter(LOG_FORMAT, datefmt=DATE_FORMAT)
    
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)
    
    # Optional file handler
    if log_file:
        file_handler = logging.FileHandler(log_file)
        file_handler.setLevel(level)
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)
    
    logger.propagate = False
    _LOGGERS[name] = logger
    return logger


class JsonFormatter(logging.Formatter):
    """JSON formatter for structured log aggregation (ELK, Splunk, etc.)"""
    
    def format(self, record: logging.LogRecord) -> str:
        log_entry = {
            "timestamp": datetime.utcnow().isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        
        # Add extra context if available
        if hasattr(record, "stage"):
            log_entry["stage"] = record.stage
        if hasattr(record, "duration_ms"):
            log_entry["duration_ms"] = record.duration_ms
        if hasattr(record, "request_id"):
            log_entry["request_id"] = record.request_id
        if hasattr(record, "file_path"):
            log_entry["file_path"] = record.file_path
        if hasattr(record, "entity_count"):
            log_entry["entity_count"] = record.entity_count
        if hasattr(record, "error"):
            log_entry["error"] = record.error
        
        return json.dumps(log_entry)


def get_logger(name: str) -> logging.Logger:
    """
    Get an existing logger or create a new one with defaults.
    
    Args:
        name: Logger name
    
    Returns:
        Logger instance
    """
    return setup_logger(name)


# Pre-configured loggers for common use cases
def get_pipeline_logger() -> logging.Logger:
    """Get logger for pipeline orchestration."""
    return get_logger("pii_engine.pipeline")


def get_parser_logger() -> logging.Logger:
    """Get logger for file parsing."""
    return get_logger("pii_engine.parser")


def get_detector_logger() -> logging.Logger:
    """Get logger for PII detection."""
    return get_logger("pii_engine.detector")


def get_resolver_logger() -> logging.Logger:
    """Get logger for entity resolution."""
    return get_logger("pii_engine.resolver")


def get_validation_logger() -> logging.Logger:
    """Get logger for output validation."""
    return get_logger("pii_engine.validation")


# Convenience logging functions with stage markers
def log_stage_start(logger: logging.Logger, stage: str, **context):
    """Log the start of a pipeline stage."""
    msg = f"[{stage}] START"
    if context:
        msg += f" | {json.dumps(context)}"
    logger.info(msg, extra={"stage": stage})


def log_stage_success(logger: logging.Logger, stage: str, duration_ms: float, **context):
    """Log successful completion of a stage."""
    msg = f"[{stage}] SUCCESS ({duration_ms:.2f}ms)"
    if context:
        context_str = " | ".join(f"{k}={v}" for k, v in context.items())
        msg += f" | {context_str}"
    logger.info(msg, extra={"stage": stage, "duration_ms": duration_ms})


def log_stage_failure(logger: logging.Logger, stage: str, error: Exception, duration_ms: float):
    """Log stage failure with error details."""
    logger.error(
        f"[{stage}] FAILED ({duration_ms:.2f}ms) | error={type(error).__name__}: {error}",
        extra={"stage": stage, "duration_ms": duration_ms, "error": str(error)},
        exc_info=True,
    )


def log_warning(logger: logging.Logger, stage: str, message: str, **context):
    """Log a warning within a stage."""
    msg = f"[{stage}] WARNING | {message}"
    if context:
        context_str = " | ".join(f"{k}={v}" for k, v in context.items())
        msg += f" | {context_str}"
    logger.warning(msg)


def log_metrics(logger: logging.Logger, stage: str, metrics: dict):
    """Log performance/quality metrics for a stage."""
    metrics_str = " | ".join(f"{k}={v}" for k, v in metrics.items())
    logger.info(f"[{stage}] METRICS | {metrics_str}")


def log_separator(logger: logging.Logger, char: str = "=", length: int = 80):
    """Log a visual separator for readability."""
    logger.info(char * length)