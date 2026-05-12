import logging
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base

from config import Config

logger = logging.getLogger(__name__)

# ── Engine ────────────────────────────────────────────────────────────────────
_is_sqlite = Config.SQLALCHEMY_DATABASE_URI.startswith("sqlite")

if _is_sqlite:
    # SQLite is a single-writer file DB. Using a connection pool with
    # pool_size > 1 causes "database is locked" when requests overlap
    # (e.g. while GLiNER runs for 20s, a second request tries to INSERT).
    # Fix: serialise all access through a single connection (StaticPool),
    # and set a 30-second busy timeout so SQLite waits instead of failing.
    from sqlalchemy.pool import StaticPool
    engine = create_engine(
        Config.SQLALCHEMY_DATABASE_URI,
        echo=Config.SQLALCHEMY_ECHO,
        connect_args={"check_same_thread": False, "timeout": 30},
        poolclass=StaticPool,
    )
else:
    engine = create_engine(
        Config.SQLALCHEMY_DATABASE_URI,
        echo=Config.SQLALCHEMY_ECHO,
        pool_size=5,
        max_overflow=10,
        pool_recycle=1800,
        pool_pre_ping=True,
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
