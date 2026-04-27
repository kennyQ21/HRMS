"""
FastAPI application entry-point.

Replaces the Flask app.py.
"""

import logging
from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI
from fastapi.middleware.cors import CORSMiddleware

from auth import verify_token
from config import UPLOADS_DIR
from database import Base, engine
from routers import connections, data, dashboard, files, redact, scan_connector, scans

# ── Logging ───────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(name)s  %(message)s",
)
logger = logging.getLogger(__name__)


# ── Lifespan: create DB tables on startup ─────────────────────────────────────
@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Starting up — ensuring DB tables exist...")
    Base.metadata.create_all(bind=engine)
    logger.info("DB tables ready.")
    UPLOADS_DIR.mkdir(parents=True, exist_ok=True)
    logger.info("Uploads directory ready: %s", UPLOADS_DIR.resolve())
    yield
    logger.info("Shutting down.")


# ── App ───────────────────────────────────────────────────────────────────────
app = FastAPI(
    title="Vault Migration Service",
    description=(
        "Connects to SQL/Mongo databases, parses files, "
        "detects PII, and migrates data to Vault."
    ),
    version="2.0.0",
    lifespan=lifespan,
    dependencies=[Depends(verify_token)],
)

# ── CORS ──────────────────────────────────────────────────────────────────────
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Routers ───────────────────────────────────────────────────────────────────
app.include_router(connections.router)
app.include_router(data.router)
app.include_router(scans.router)
app.include_router(files.router)
app.include_router(redact.router)
app.include_router(scan_connector.router)
app.include_router(dashboard.router)


# ── Dev entrypoint ────────────────────────────────────────────────────────────
if __name__ == "__main__":
    import uvicorn

    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
