"""
Vault Migration Service — FastAPI entry-point.

Single endpoint:  POST /scan-file
"""
from __future__ import annotations

import logging
import os
import threading
from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI
from fastapi.middleware.cors import CORSMiddleware

from auth import verify_token
from config import UPLOADS_DIR
from database import Base, engine
from routers.scan import router as scan_router


# ── Terminal logging — clear, colourised, stage-friendly ─────────────────────

class _StageFormatter(logging.Formatter):
    """
    Adds colour to log levels so pipeline stages are easy to follow
    in the terminal even without a log viewer.

        grey   = DEBUG
        white  = INFO
        yellow = WARNING
        red    = ERROR / CRITICAL
    """
    _GREY    = "\x1b[38;5;245m"
    _WHITE   = "\x1b[0m"
    _YELLOW  = "\x1b[33m"
    _RED     = "\x1b[31;1m"
    _RESET   = "\x1b[0m"

    _COLOURS = {
        logging.DEBUG:    _GREY,
        logging.INFO:     _WHITE,
        logging.WARNING:  _YELLOW,
        logging.ERROR:    _RED,
        logging.CRITICAL: _RED,
    }

    _FMT = "%(asctime)s  %(levelname)-8s  %(message)s"

    def format(self, record: logging.LogRecord) -> str:
        colour = self._COLOURS.get(record.levelno, self._WHITE)
        formatter = logging.Formatter(
            fmt=f"{colour}{self._FMT}{self._RESET}",
            datefmt="%H:%M:%S",
        )
        return formatter.format(record)


def _setup_logging():
    handler = logging.StreamHandler()
    handler.setFormatter(_StageFormatter())

    root = logging.getLogger()
    root.setLevel(logging.INFO)
    root.handlers.clear()
    root.addHandler(handler)

    # Silence noisy third-party loggers
    for noisy in ("uvicorn.access", "httpx", "httpcore",
                  "ppocr", "paddle", "PIL", "matplotlib",
                  "presidio_analyzer", "presidio-analyzer",
                  "transformers.tokenization_utils_base"):
        logging.getLogger(noisy).setLevel(logging.ERROR)

    # Keep uvicorn error logs visible
    logging.getLogger("uvicorn.error").setLevel(logging.INFO)


_setup_logging()
logger = logging.getLogger(__name__)


# ── OCR warm-up ───────────────────────────────────────────────────────────────

def _warm_ocr():
    """Load PaddleOCR mobile models into RAM at startup (background thread)."""
    try:
        logger.info("── OCR warm-up: loading PaddleOCR mobile models …")
        from services.ocr_engine import _get_ocr
        _get_ocr()
        logger.info("── OCR warm-up complete ✓")
    except Exception as exc:
        logger.warning("── OCR warm-up failed (non-fatal): %s", exc)


# ── Ollama auto-start ──────────────────────────────────────────────────────────

def _ensure_ollama():
    """
    Start Ollama if not already running (background thread).
    Required for multilingual + medical PII detection via Qwen 0.5B.
    """
    import subprocess, time, requests as _req, shutil
    try:
        r = _req.get("http://localhost:11434/api/tags", timeout=2)
        if r.status_code == 200:
            logger.info("── Ollama already running ✓ (Qwen 0.5B available)")
            return
    except Exception:
        pass

    if not shutil.which("ollama"):
        logger.warning("── Ollama not found — multilingual PII detection disabled")
        return

    try:
        logger.info("── Starting Ollama for multilingual detection …")
        subprocess.Popen(
            ["ollama", "serve"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        # Wait up to 10 s for Ollama to become ready
        for _ in range(10):
            time.sleep(1)
            try:
                r = _req.get("http://localhost:11434/api/tags", timeout=1)
                if r.status_code == 200:
                    logger.info("── Ollama started ✓  (qwen2.5:0.5b ready for multilingual PII)")
                    return
            except Exception:
                continue
        logger.warning("── Ollama did not respond in time — multilingual PII detection may be unavailable")
    except Exception as exc:
        logger.warning("── Could not start Ollama: %s", exc)


# ── Lifespan ──────────────────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("═" * 60)
    logger.info("  Vault Migration Service  —  starting up")
    logger.info("═" * 60)

    Base.metadata.create_all(bind=engine)
    logger.info("  DB tables   ✓")

    UPLOADS_DIR.mkdir(parents=True, exist_ok=True)
    logger.info("  Uploads dir ✓  (%s)", UPLOADS_DIR.resolve())

    threading.Thread(target=_warm_ocr, daemon=True, name="ocr-warmup").start()

    logger.info("  Endpoint    →  POST /scan-file")
    logger.info("  Docs        →  http://localhost:5000/docs")
    logger.info("═" * 60)

    yield

    logger.info("═" * 60)
    logger.info("  Vault Migration Service  —  shutting down")
    logger.info("═" * 60)


# ── App ───────────────────────────────────────────────────────────────────────

app = FastAPI(
    title="Vault Migration Service",
    description="Upload a file → detect PII → receive structured JSON.",
    version="3.0.0",
    lifespan=lifespan,
    dependencies=[Depends(verify_token)],
)

_CORS_ORIGINS = [o.strip() for o in os.getenv("CORS_ORIGINS", "*").split(",") if o.strip()]

app.add_middleware(
    CORSMiddleware,
    allow_origins=_CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(scan_router)


# ── Dev entrypoint ────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        reload_dirs=[".", "routers", "services", "parsers", "utils"],
        reload_excludes=["venv", "uploads", "debug", "results", "__pycache__", "*.pyc"],
        log_config=None,   # use our own logging setup, not uvicorn's default
    )
