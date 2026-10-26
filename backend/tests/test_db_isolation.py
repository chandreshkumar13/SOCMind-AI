"""The test session must never touch a developer's database."""
import os
import subprocess
import sys

from app.core.config import settings
from app.db.session import engine

BACKEND_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))


def test_session_database_is_a_throw_away_temp_file():
    path = os.path.abspath(engine.url.database)
    assert "socmind-tests-" in path
    assert path != os.path.abspath(os.path.join(BACKEND_DIR, "socmind.db"))
    assert settings.DATABASE_URL == os.environ["DATABASE_URL"]


def test_a_database_url_in_the_environment_is_ignored_by_the_tests(tmp_path):
    decoy = tmp_path / "developer.db"
    env = {**os.environ, "DATABASE_URL": f"sqlite:///{decoy.as_posix()}", "PYTHONDONTWRITEBYTECODE": "1"}
    result = subprocess.run(
        [sys.executable, "-m", "pytest", "-p", "no:cacheprovider", "-q", "--no-header", "-W", "ignore", "tests/test_alerts.py"],
        cwd=BACKEND_DIR, env=env, capture_output=True, text=True, timeout=240,
    )
    assert result.returncode == 0, result.stdout[-1500:] + result.stderr[-500:]
    assert not decoy.exists(), "the test session opened the database named by DATABASE_URL"
