"""Shared pytest fixtures.

`iso_client` gives each test its own temporary SQLite database, so new tests never read from or
modify the real socmind.db file. (The older tests in test_alerts.py use the shared database.)
"""
import pytest
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
