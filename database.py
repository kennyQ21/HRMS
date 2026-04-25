import logging
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base

from config import Config

logger = logging.getLogger(__name__)

# ── Engine ────────────────────────────────────────────────────────────────────
engine = create_engine(
    Config.SQLALCHEMY_DATABASE_URI,
    echo=Config.SQLALCHEMY_ECHO,
    # For SQLite in dev: allow use across threads (FastAPI creates threads
    # via run_in_threadpool). Ignored for other dialects.
    connect_args={"check_same_thread": False}
    if Config.SQLALCHEMY_DATABASE_URI.startswith("sqlite")
    else {},
)

# ── Session factory ───────────────────────────────────────────────────────────
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# ── Declarative base (shared with models.py) ──────────────────────────────────
Base = declarative_base()


# ── FastAPI dependency ────────────────────────────────────────────────────────
def get_db():
    """
    Yield a SQLAlchemy session and guarantee it is closed after the request,
    even if an exception is raised. Plug into routes via Depends(get_db).
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
