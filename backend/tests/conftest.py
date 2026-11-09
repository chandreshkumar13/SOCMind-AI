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

# Threat-intelligence lookups stay on the offline mock in tests, whatever a developer has in the shell or in a .env
# file. An empty key counts as "not configured". Tests that need live behaviour enable it explicitly, with a fake
# key and a mocked HTTP transport.
os.environ["THREAT_INTEL_PROVIDER"] = "mock"
os.environ["VIRUSTOTAL_API_KEY"] = ""


def pytest_sessionfinish(session, exitstatus):
    """Release the SQLite file (Windows cannot delete an open file) and remove the throw-away directory."""
    from app.db.session import engine
    engine.dispose()
    shutil.rmtree(_SESSION_DB_DIR, ignore_errors=True)


import socket  # noqa: E402
import pytest  # noqa: E402  (must come after DATABASE_URL is set)
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.main import app
from app.db.session import get_db
from app.models.base import Base


_LOCAL_HOSTS = {"127.0.0.1", "::1", "localhost", "0.0.0.0", ""}
_real_connect = socket.socket.connect
_real_getaddrinfo = socket.getaddrinfo


@pytest.fixture(autouse=True)
def _no_outbound_network(monkeypatch):
    """No test may reach the internet (a real VirusTotal call would spend quota and leak indicators)."""
    def guarded_connect(self, address):
        host = address[0] if isinstance(address, tuple) else None
        if host is not None and host not in _LOCAL_HOSTS:
            raise RuntimeError(f"Outbound network access is blocked in tests (tried to connect to {host}).")
        return _real_connect(self, address)

    def guarded_getaddrinfo(host, *args, **kwargs):
        if host not in _LOCAL_HOSTS and host is not None:
            raise RuntimeError(f"Outbound network access is blocked in tests (tried to resolve {host}).")
        return _real_getaddrinfo(host, *args, **kwargs)

    monkeypatch.setattr(socket.socket, "connect", guarded_connect)
    monkeypatch.setattr(socket, "getaddrinfo", guarded_getaddrinfo)


@pytest.fixture(autouse=True)
def _fresh_threat_intel_client():
    """The live client keeps quota counters and a cache; every test starts with none."""
    from app.services.threat_intel import reset_client
    reset_client()
    yield
    reset_client()


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
