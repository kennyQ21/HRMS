"""
Alembic env.py — adapted for FastAPI / plain SQLAlchemy.

Removed Flask-SQLAlchemy / Flask-Migrate dependencies.
Reads the DB URL directly from config.py and imports the
declarative Base from database.py so autogenerate works.
"""

import logging
from logging.config import fileConfig

from alembic import context
from sqlalchemy import engine_from_config, pool

# ── Project imports ───────────────────────────────────────────────────────────
# database.py holds the declarative Base that all models inherit from.
# Importing models here ensures Alembic can see every table for autogenerate.
from database import Base, engine  # noqa: F401
import models  # noqa: F401  — registers Scan, ColumnScan, ScanAnomaly with Base

from config import Config

# ── Alembic config ────────────────────────────────────────────────────────────
alembic_cfg = context.config

# Set the SQLAlchemy URL from our app config (overrides alembic.ini value)
alembic_cfg.set_main_option("sqlalchemy.url", Config.SQLALCHEMY_DATABASE_URI)

# Set up Python logging from alembic.ini if a config file is present
if alembic_cfg.config_file_name:
    fileConfig(alembic_cfg.config_file_name)

logger = logging.getLogger("alembic.env")

# target_metadata enables --autogenerate support
target_metadata = Base.metadata


# ── Offline migrations ────────────────────────────────────────────────────────

def run_migrations_offline():
    """
    Run migrations without a live DB connection.
    The URL is emitted as a string into the migration script output.
    """
    url = alembic_cfg.get_main_option("sqlalchemy.url")
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )

    with context.begin_transaction():
        context.run_migrations()


# ── Online migrations ─────────────────────────────────────────────────────────

def run_migrations_online():
    """
    Run migrations with a live DB connection.
    Reuses the engine already created in database.py so we don't open
    a second connection pool.
    """
    def process_revision_directives(ctx, revision, directives):
        """Skip generating an empty migration script."""
        if getattr(alembic_cfg.cmd_opts, "autogenerate", False):
            script = directives[0]
            if script.upgrade_ops.is_empty():
                directives[:] = []
                logger.info("No schema changes detected — skipping empty migration.")

    with engine.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            process_revision_directives=process_revision_directives,
        )

        with context.begin_transaction():
            context.run_migrations()


# ── Entry-point ───────────────────────────────────────────────────────────────
if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
