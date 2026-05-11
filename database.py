import logging
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base

from config import Config

logger = logging.getLogger(__name__)

# ── Engine ────────────────────────────────────────────────────────────────────
_is_sqlite = Config.SQLALCHEMY_DATABASE_URI.startswith("sqlite")

engine = create_engine(
    Config.SQLALCHEMY_DATABASE_URI,
    echo=Config.SQLALCHEMY_ECHO,
    connect_args={"check_same_thread": False} if _is_sqlite else {},
    # Pool limits — prevent connection storms under load.
    # SQLite uses StaticPool so pool_size/max_overflow are ignored for it.
    pool_size=5,
    max_overflow=10,
    pool_recycle=1800,   # recycle connections every 30 min (avoids stale TCP)
    pool_pre_ping=True,  # validate connections before use
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
