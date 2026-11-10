"""Housekeeping (C16): timezone-aware clock calls, no unused declared dependency, and a verification script that never touches
the project database."""
import ast
import hashlib
import os
import subprocess
import sys
from pathlib import Path

BACKEND = Path(__file__).resolve().parents[1]
APP = BACKEND / "app"


def _app_sources():
    return [p for p in APP.rglob("*.py") if "__pycache__" not in p.parts]


def test_no_deprecated_utcnow_calls_remain_in_the_application():
    offenders = [str(p.relative_to(BACKEND)) for p in _app_sources() if "utcnow(" in p.read_text(encoding="utf-8")]
    assert offenders == []


def test_the_clock_helper_returns_naive_utc_like_the_old_calls_did():
    from app.core.clock import utc_now
    value = utc_now()
    assert value.tzinfo is None
    assert abs((value - __import__("datetime").datetime.utcnow()).total_seconds()) < 5


def test_requests_is_not_a_declared_dependency_because_nothing_imports_it():
    declared = [line.split(">")[0].split("=")[0].strip().lower() for line in
                (BACKEND / "requirements.txt").read_text(encoding="utf-8").splitlines() if line.strip() and not line.startswith("#")]
    assert "requests" not in declared
    for p in _app_sources():
        assert "import requests" not in p.read_text(encoding="utf-8"), p


def _unused_imports(path: Path):
    tree = ast.parse(path.read_text(encoding="utf-8"))
    imported = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                imported[(alias.asname or alias.name).split(".")[0]] = node.lineno
        elif isinstance(node, ast.ImportFrom):
            for alias in node.names:
                imported[alias.asname or alias.name] = node.lineno
    used = {n.id for n in ast.walk(tree) if isinstance(n, ast.Name)} | {n.value.id for n in ast.walk(tree)
                                                                       if isinstance(n, ast.Attribute) and isinstance(n.value, ast.Name)}
    source_lines = path.read_text(encoding="utf-8").splitlines()
    return sorted(name for name, line in imported.items()
                  if name not in used and "noqa" not in source_lines[line - 1] and name not in ("annotations",))


def test_the_application_has_no_unused_imports():
    report = {str(p.relative_to(BACKEND)): _unused_imports(p) for p in _app_sources()}
    report = {k: v for k, v in report.items() if v and not k.endswith("__init__.py")}
    assert report == {}, report


def test_the_verification_script_uses_a_temporary_database_and_leaves_the_project_database_alone():
    project_db = BACKEND / "socmind.db"
    before = hashlib.sha256(project_db.read_bytes()).hexdigest() if project_db.exists() else None
    env = dict(os.environ)
    env.pop("DATABASE_URL", None)
    result = subprocess.run([sys.executable, str(BACKEND / "verify_preservation.py")], cwd=str(BACKEND), env=env,
                            capture_output=True, text=True, timeout=120)
    assert result.returncode == 0, result.stdout + result.stderr
    assert "ALL ASSERTIONS PASSED" in result.stdout
    after = hashlib.sha256(project_db.read_bytes()).hexdigest() if project_db.exists() else None
    assert before == after
