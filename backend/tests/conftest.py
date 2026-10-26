"""Shared pytest fixtures and test-database isolation.

The whole test session runs against a throw-away SQLite file in the system temp directory. DATABASE_URL is
forced here, BEFORE the application is imported, so neither a developer's socmind.db nor a DATABASE_URL set in the
shell or in a .env file can ever be read or modified by the tests. (Environment variables take precedence over .env.)

`iso_client` additionally gives each test its own temporary database for tests that need a clean slate; the older
modules (test_alerts.py, test_enrichment.py) share the session database.
"""
import atexit
import os
import shutil
import tempfile

_SESSION_DB_DIR = tempfile.mkdtemp(prefix="socmind-tests-")
os.environ["DATABASE_URL"] = "sqlite:///" + os.path.join(_SESSION_DB_DIR, "session.db").replace("\\", "/")
atexit.register(shutil.rmtree, _SESSION_DB_DIR, ignore_errors=True)


def pytest_sessionfinish(session, exitstatus):
    """Release the SQLite file (Windows cannot delete an open file) and remove the throw-away directory."""
    from app.db.session import engine
    engine.dispose()
    shutil.rmtree(_SESSION_DB_DIR, ignore_errors=True)


import pytest  # noqa: E402  (must come after DATABASE_URL is set)
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.main import app
from app.db.session import get_db
from app.models.base import Base


@pytest.fixture
def iso_client(tmp_path):
    from app.models import models  # noqa: F401  (register tables)
    engine = create_engine(
        f"sqlite:///{tmp_path / 'test.db'}", connect_args={"check_same_thread": False}
    )
    Base.metadata.create_all(bind=engine)
    TestingSession = sessionmaker(autocommit=False, autoflush=False, bind=engine)

    def override_get_db():
        db = TestingSession()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_get_db
    client = TestClient(app, raise_server_exceptions=False)
    client.session_factory = TestingSession
    yield client
    app.dependency_overrides.pop(get_db, None)
    engine.dispose()
