import os
from sqlalchemy import create_engine, inspect, text
from sqlalchemy.orm import sessionmaker, Session
from app.core.config import settings
from app.models.base import Base

# Ensure SQLite connection allows multi-thread access for FastAPI
connect_args = {"check_same_thread": False} if settings.DATABASE_URL.startswith("sqlite") else {}

engine = create_engine(
    settings.DATABASE_URL,
    connect_args=connect_args,
    echo=False
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Safely add columns introduced after the initial database schema.
_ADDED_COLUMNS = {"incidents": {"details": "JSON"}}

def ensure_columns(bind=None):
    bind = bind or engine
    insp = inspect(bind)
    existing_tables = set(insp.get_table_names())
    for table, columns in _ADDED_COLUMNS.items():
        if table not in existing_tables:
            continue
        present = {c["name"] for c in insp.get_columns(table)}
        for name, sql_type in columns.items():
            if name not in present:
                with bind.begin() as conn:
                    conn.execute(text(f"ALTER TABLE {table} ADD COLUMN {name} {sql_type}"))


def init_db():
    """
    Initializes database tables if they do not already exist.
    """
    from app.models.models import AlertModel, IncidentModel, AuditLogModel  # noqa
    Base.metadata.create_all(bind=engine)
    ensure_columns(engine)


def get_db():
    """
    FastAPI dependency yielding a database session.
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
