"""Security checks for the accounts mode, written to the audit list in docs/SECURITY.md. Each test uses its own temporary database."""
import hashlib

import pytest

from app.core.config import settings
from app.models.auth_models import AuthSession, UserAccount
from app.services import accounts

API = "/api/v1"
PASSWORD = "a long enough passphrase"


@pytest.fixture
def accounts_mode(monkeypatch):
    monkeypatch.setattr(settings, "AUTH_MODE", "accounts")
    monkeypatch.setattr(settings, "AUTH_TOKENS", [])
    yield


def make_user(client, username, role, password=PASSWORD):
    db = client.session_factory()
    try:
        accounts.create_user(db, username, role, password)
    finally:
        db.close()


def sign_in(client, username, password=PASSWORD):
    return client.post(f"{API}/auth/login", json={"username": username, "password": password})


# ----------------------------------------------------------------------------------- what is stored
def test_passwords_are_stored_only_as_scrypt_hashes(iso_client, accounts_mode):
    make_user(iso_client, "ana.analyst", "analyst")
    db = iso_client.session_factory()
    try:
        row = db.query(UserAccount).filter(UserAccount.username == "ana.analyst").one()
        assert row.password_hash.startswith("scrypt$") and PASSWORD not in row.password_hash
    finally:
        db.close()


def test_the_database_holds_no_session_token_and_no_csrf_value(iso_client, accounts_mode):
    make_user(iso_client, "ana.analyst", "analyst")
    login = sign_in(iso_client, "ana.analyst")
    cookie = iso_client.cookies.get("socmind_session")
    csrf = login.json()["csrf_token"]
    db = iso_client.session_factory()
    try:
        rows = db.query(AuthSession).all()
        assert len(rows) == 1
        stored = rows[0]
        assert stored.id == hashlib.sha256(cookie.encode()).hexdigest(), "only the SHA-256 of the cookie is kept"
        all_values = [str(getattr(stored, c.name)) for c in AuthSession.__table__.columns]
        assert cookie not in all_values and csrf not in all_values
    finally:
        db.close()


def test_the_session_cookie_is_long_and_random(iso_client, accounts_mode):
    make_user(iso_client, "ana.analyst", "analyst")
    sign_in(iso_client, "ana.analyst")
    cookie = iso_client.cookies.get("socmind_session")
    assert len(cookie) >= 43, "token_urlsafe(32) gives 43 characters"


# ----------------------------------------------------------------------------------- what is revealed
def test_a_disabled_account_gets_exactly_the_same_answer_as_a_wrong_password(iso_client, accounts_mode):
    make_user(iso_client, "ana.analyst", "analyst")
    make_user(iso_client, "ben.builder", "viewer")
    db = iso_client.session_factory()
    try:
        accounts.set_active(db, "ben.builder", False)
    finally:
        db.close()
    wrong = sign_in(iso_client, "ana.analyst", "wrong-wrong-wrong")
    disabled = sign_in(iso_client, "ben.builder")
    unknown = sign_in(iso_client, "no-such-person", "wrong-wrong-wrong")
    assert wrong.status_code == disabled.status_code == unknown.status_code == 401
    assert wrong.json() == disabled.json() == unknown.json()


def test_the_public_status_reveals_only_the_mode_and_whether_sign_in_is_used(iso_client, accounts_mode):
    body = iso_client.get(f"{API}/auth/status").json()
    assert set(body) == {"mode", "login_required", "sign_in"}


def test_an_oversized_username_is_refused_without_a_server_error(iso_client, accounts_mode):
    res = sign_in(iso_client, "x" * 300, PASSWORD)
    assert res.status_code == 422


# ----------------------------------------------------------------------------------- roles through cookies
@pytest.mark.parametrize("role,route,method,allowed", [
    ("viewer", "/alerts/seed", "post", False),          # analyst needed
    ("analyst", "/alerts/seed", "post", True),
    ("viewer", "/alerts", "get", True),
    ("analyst", "/incidents/NO-SUCH/approve", "post", False),    # approver needed
    ("approver", "/incidents/NO-SUCH/approve", "post", True),   # passes the role check; 404 for a missing incident
])
def test_roles_are_enforced_for_cookie_sessions(iso_client, accounts_mode, role, route, method, allowed):
    make_user(iso_client, f"{role}.person", role)
    login = sign_in(iso_client, f"{role}.person")
    headers = {"X-CSRF-Token": login.json()["csrf_token"]} if method != "get" else {}
    body = {"reviewer": "x"} if "approve" in route else None
    res = getattr(iso_client, method)(f"{API}{route}", headers=headers, json=body) if body else getattr(iso_client, method)(f"{API}{route}", headers=headers)
    if allowed:
        assert res.status_code not in (401, 403), res.status_code
    else:
        assert res.status_code == 403, res.status_code


# ----------------------------------------------------------------------------------- CORS and credentials
def test_cors_allows_credentials_for_the_listed_frontend_origin_only(iso_client, accounts_mode):
    allowed = iso_client.options(f"{API}/auth/logout", headers={
        "Origin": "http://localhost:5173", "Access-Control-Request-Method": "POST",
        "Access-Control-Request-Headers": "content-type,x-csrf-token"})
    assert allowed.headers.get("access-control-allow-origin") == "http://localhost:5173"
    assert allowed.headers.get("access-control-allow-credentials") == "true"
    assert "x-csrf-token" in allowed.headers.get("access-control-allow-headers", "").lower()
    refused = iso_client.options(f"{API}/auth/logout", headers={
        "Origin": "https://attacker.example", "Access-Control-Request-Method": "POST"})
    assert refused.headers.get("access-control-allow-origin") is None
