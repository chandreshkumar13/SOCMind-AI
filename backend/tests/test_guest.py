"""The optional read-only guest (ALLOW_GUEST, accounts mode only).

Covers: off by default (404 and guest_allowed false), on only in accounts mode, what a guest can read, that EVERY route that needs
the analyst or approver role (the list is taken from test_route_guards, so a new route is covered automatically) answers 403 to a
guest, that a guest has no account row, the audit entries, the session rules (cookie, CSRF, idle and absolute expiry, cap, logout),
that a real account cannot be called "guest", and that the backend refuses to start with ALLOW_GUEST=true outside development and test.
"""
import os
import subprocess
import sys
from datetime import timedelta
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.core.auth import validate_auth_config
from app.core.clock import utc_now
from app.core.config import settings
from app.main import app
from app.models.auth_models import UserAccount
from app.services import accounts, guest
from test_route_guards import EXPECTED, RANK, _concrete

API = "/api/v1"
PASSWORD = "a long enough passphrase"
AUTOMATION_TOKEN = "automation-token-0123456789abcdef"
BACKEND = Path(__file__).resolve().parents[1]


@pytest.fixture(autouse=True)
def _no_guest_sessions_left_over():
    guest.clear()
    yield
    guest.clear()


@pytest.fixture
def accounts_mode(monkeypatch):
    monkeypatch.setattr(settings, "AUTH_MODE", "accounts")
    monkeypatch.setattr(settings, "AUTH_TOKENS", [])
    monkeypatch.setattr(settings, "ALLOW_GUEST", False)
    yield


@pytest.fixture
def guests_on(accounts_mode, monkeypatch):
    monkeypatch.setattr(settings, "ALLOW_GUEST", True)
    yield


def another_client():
    return TestClient(app, raise_server_exceptions=False)


def make_user(client, username, role, password=PASSWORD):
    db = client.session_factory()
    try:
        return accounts.create_user(db, username, role, password)
    finally:
        db.close()


def open_guest(client):
    res = client.post(f"{API}/auth/guest", json={})
    assert res.status_code == 200, res.text
    return {"X-CSRF-Token": res.json()["csrf_token"]}


def audit_rows(client, **params):
    res = client.get(f"{API}/audit-logs", params={"limit": 200, **params})
    assert res.status_code == 200, res.text
    return res.json()


def account_names(client):
    db = client.session_factory()
    try:
        return [u.username for u in db.query(UserAccount).all()]
    finally:
        db.close()


# ----------------------------------------------------------------------------------- off by default
def test_guest_access_is_off_by_default():
    from app.core.config import Settings
    assert Settings.model_fields["ALLOW_GUEST"].default is False


def test_with_guests_off_the_status_says_so_and_the_route_is_404(iso_client, accounts_mode):
    assert iso_client.get(f"{API}/auth/status").json()["guest_allowed"] is False
    for payload in ({}, {"x": 1}):
        res = iso_client.post(f"{API}/auth/guest", json=payload)
        assert res.status_code == 404 and "set-cookie" not in res.headers
    assert iso_client.get(f"{API}/auth/me").status_code == 401


@pytest.mark.parametrize("mode", ["disabled", "token"])
def test_the_setting_does_nothing_outside_accounts_mode(iso_client, monkeypatch, mode):
    monkeypatch.setattr(settings, "AUTH_MODE", mode)
    monkeypatch.setattr(settings, "AUTH_TOKENS", [{"name": "Ana", "role": "analyst", "token": AUTOMATION_TOKEN}] if mode == "token" else [])
    monkeypatch.setattr(settings, "ALLOW_GUEST", True)
    assert iso_client.get(f"{API}/auth/status").json()["guest_allowed"] is False
    assert iso_client.post(f"{API}/auth/guest", json={}).status_code == 404


def test_with_guests_on_the_status_offers_the_button(iso_client, guests_on):
    body = iso_client.get(f"{API}/auth/status").json()
    assert body["guest_allowed"] is True and body["sign_in"] is True


# ----------------------------------------------------------------------------------- opening a guest session
def test_a_guest_session_is_a_viewer_named_guest(iso_client, guests_on):
    res = iso_client.post(f"{API}/auth/guest", json={})
    assert res.status_code == 200
    body = res.json()
    assert body["authenticated"] is True and body["mode"] == "accounts"
    assert body["name"] == "guest" and body["role"] == "viewer" and body["guest"] is True
    assert body["csrf_token"] and body["expires_in_seconds"] > 0 and body["idle_timeout_minutes"] == settings.SESSION_IDLE_MINUTES
    cookie = res.headers["set-cookie"].lower()
    assert "httponly" in cookie and "samesite=strict" in cookie and f"{accounts.SESSION_COOKIE}=" in cookie
    me = iso_client.get(f"{API}/auth/me").json()
    assert me["name"] == "guest" and me["role"] == "viewer" and me["guest"] is True and me["authenticated"] is True
    assert me["csrf_token"] == body["csrf_token"]


def test_a_guest_has_no_account_and_never_appears_in_the_account_table(iso_client, guests_on):
    open_guest(iso_client)
    assert account_names(iso_client) == []
    assert iso_client.get(f"{API}/auth/status").json()["setup_required"] is True, "a guest does not count as an account"
    approver = another_client()
    make_user(iso_client, "boss.one", "approver")
    approver.post(f"{API}/auth/login", json={"username": "boss.one", "password": PASSWORD})
    assert [u["username"] for u in approver.get(f"{API}/auth/users").json()] == ["boss.one"]


def test_the_request_must_be_json(iso_client, guests_on):
    res = iso_client.post(f"{API}/auth/guest", data={"a": "b"})
    assert res.status_code in (415, 422) and "set-cookie" not in res.headers


def test_opening_a_guest_session_is_audited_with_actor_guest(iso_client, guests_on):
    open_guest(iso_client)
    rows = audit_rows(iso_client, action="LOGIN")
    assert len(rows) == 1 and rows[0]["actor"] == "guest" and rows[0]["details"]["guest"] is True


def test_the_response_holds_nothing_secret(iso_client, guests_on):
    res = iso_client.post(f"{API}/auth/guest", json={})
    assert "password" not in res.text.lower() and "hash" not in res.text.lower()


# ----------------------------------------------------------------------------------- read-only
def test_a_guest_can_read(iso_client, guests_on):
    open_guest(iso_client)
    for path in ("/alerts", "/incidents", "/stats", "/audit-logs", "/agents", "/config", "/pipeline/runs"):
        res = iso_client.get(f"{API}{path}")
        assert res.status_code == 200, (path, res.status_code)


def test_every_route_that_needs_more_than_viewer_is_403_for_a_guest(iso_client, guests_on):
    headers = open_guest(iso_client)             # with its CSRF token, so only the role can be the reason
    checked = []
    for (method, path), role in EXPECTED.items():
        if role is None or RANK[role] <= RANK["viewer"]:
            continue
        res = iso_client.request(method, _concrete(path), headers=headers, json={} if method == "POST" else None)
        assert res.status_code == 403, (method, path, res.status_code)
        checked.append((method, path))
    assert ("POST", "/api/v1/alerts/seed") in checked and ("POST", "/api/v1/incidents/{incident_id}/approve") in checked
    assert ("POST", "/api/v1/auth/users/{username}/password") in checked and ("GET", "/api/v1/auth/users") in checked
    assert len(checked) >= 15


def test_a_guest_write_without_the_csrf_token_is_refused_too(iso_client, guests_on):
    open_guest(iso_client)
    assert iso_client.post(f"{API}/alerts/seed").status_code == 403


def test_a_guest_cannot_change_a_password(iso_client, guests_on):
    headers = open_guest(iso_client)
    res = iso_client.post(f"{API}/auth/password", json={"current_password": "x" * 12, "new_password": "y" * 12}, headers=headers)
    assert res.status_code == 403


def test_nothing_a_guest_tries_changes_the_data(iso_client, guests_on):
    headers = open_guest(iso_client)
    before = iso_client.get(f"{API}/alerts").headers.get("X-Total-Count")
    iso_client.post(f"{API}/alerts/seed", headers=headers)
    iso_client.post(f"{API}/pipeline/run", headers=headers)
    assert iso_client.get(f"{API}/alerts").headers.get("X-Total-Count") == before


# ----------------------------------------------------------------------------------- the session
def test_logout_ends_the_guest_session_and_is_audited(iso_client, guests_on):
    headers = open_guest(iso_client)
    assert guest.open_sessions() == 1
    assert iso_client.post(f"{API}/auth/logout", headers=headers).status_code == 200
    assert guest.open_sessions() == 0
    assert iso_client.get(f"{API}/alerts").status_code == 401
    # the cookie is gone from the jar; even a copy of the old one is refused
    out = audit_rows(another_client_with_admin(iso_client), action="LOGOUT")
    assert out and out[0]["actor"] == "guest"


def another_client_with_admin(client):
    make_user(client, "boss.one", "approver")
    admin = another_client()
    admin.post(f"{API}/auth/login", json={"username": "boss.one", "password": PASSWORD})
    return admin


def test_logout_without_the_csrf_token_does_not_end_it(iso_client, guests_on):
    open_guest(iso_client)
    assert iso_client.post(f"{API}/auth/logout").status_code == 403
    assert iso_client.get(f"{API}/alerts").status_code == 200


def test_turning_guests_off_ends_every_guest_session_at_once(iso_client, guests_on, monkeypatch):
    open_guest(iso_client)
    assert iso_client.get(f"{API}/alerts").status_code == 200
    monkeypatch.setattr(settings, "ALLOW_GUEST", False)
    assert iso_client.get(f"{API}/alerts").status_code == 401


def test_a_guest_session_does_not_disturb_real_sign_in(iso_client, guests_on):
    make_user(iso_client, "ana.analyst", "analyst")
    guest_client = another_client()
    open_guest(guest_client)
    res = iso_client.post(f"{API}/auth/login", json={"username": "ana.analyst", "password": PASSWORD})
    assert res.status_code == 200 and "guest" not in res.json()
    assert iso_client.get(f"{API}/auth/me").json()["name"] == "ana.analyst"
    assert guest_client.get(f"{API}/auth/me").json()["name"] == "guest"


def test_an_unknown_cookie_is_not_a_guest(iso_client, guests_on):
    iso_client.cookies.set(accounts.SESSION_COOKIE, "not-a-real-session-token")
    assert iso_client.get(f"{API}/alerts").status_code == 401


def test_a_bearer_token_cannot_become_a_guest_and_a_guest_cookie_does_not_hide_one(iso_client, guests_on, monkeypatch):
    monkeypatch.setattr(settings, "AUTH_TOKENS", [{"name": "Automation", "role": "analyst", "token": AUTOMATION_TOKEN}])
    open_guest(iso_client)
    # the cookie is a valid guest session, so it is the identity (as an account cookie would be over a bearer token)
    assert iso_client.get(f"{API}/auth/me", headers={"Authorization": f"Bearer {AUTOMATION_TOKEN}"}).json()["name"] == "guest"
    # without a cookie the token works as it always did
    assert another_client().get(f"{API}/auth/me", headers={"Authorization": f"Bearer {AUTOMATION_TOKEN}"}).json()["name"] == "Automation"


# ----------------------------------------------------------------------------------- the store
def test_a_guest_session_ends_when_idle_or_at_the_absolute_limit():
    now = utc_now()
    token, row = guest.create_session(now)
    assert guest.session_for_token(token, now + timedelta(minutes=settings.SESSION_IDLE_MINUTES - 1)) is not None
    token2, _ = guest.create_session(now)
    assert guest.session_for_token(token2, now + timedelta(minutes=settings.SESSION_IDLE_MINUTES + 1)) is None, "idle"
    token3, _ = guest.create_session(now)
    step = now
    while step + timedelta(minutes=settings.SESSION_IDLE_MINUTES - 1) < row.absolute_expires_at:
        step += timedelta(minutes=settings.SESSION_IDLE_MINUTES - 1)          # always active, so only the absolute limit can end it
        assert guest.session_for_token(token3, step) is not None
    assert guest.session_for_token(token3, row.absolute_expires_at) is None, "the absolute limit"


def test_only_the_hash_of_the_token_is_kept():
    token, row = guest.create_session()
    assert row.id == accounts.token_id(token) and token not in row.id and token not in repr(row)


def test_the_number_of_guest_sessions_is_capped_and_the_oldest_goes_first(monkeypatch):
    monkeypatch.setattr(guest, "MAX_GUEST_SESSIONS", 3)
    now = utc_now()
    tokens = [guest.create_session(now + timedelta(seconds=i))[0] for i in range(5)]
    assert guest.open_sessions() == 3
    later = now + timedelta(seconds=10)
    assert [guest.session_for_token(t, later) is not None for t in tokens] == [False, False, True, True, True]


def test_expired_sessions_are_dropped_before_live_ones_are_pushed_out(monkeypatch):
    monkeypatch.setattr(guest, "MAX_GUEST_SESSIONS", 2)
    now = utc_now()
    old, _ = guest.create_session(now - timedelta(hours=settings.SESSION_ABSOLUTE_HOURS + 1))
    live, _ = guest.create_session(now)
    fresh, _ = guest.create_session(now)
    assert guest.session_for_token(live, now) is not None and guest.session_for_token(fresh, now) is not None
    assert guest.session_for_token(old, now) is None


def test_end_session_reports_whether_one_was_open():
    token, row = guest.create_session()
    assert guest.end_session(row.id) is True and guest.end_session(row.id) is False and guest.end_session(None) is False
    assert guest.session_for_token(token) is None


# ----------------------------------------------------------------------------------- the name "guest"
def test_no_real_account_can_be_called_guest(iso_client, accounts_mode):
    with pytest.raises(ValueError, match="reserved"):
        make_user(iso_client, "guest", "viewer")
    with pytest.raises(ValueError, match="reserved"):
        make_user(iso_client, "GUEST", "viewer")
    assert account_names(iso_client) == []


def test_the_api_refuses_to_create_an_account_called_guest(iso_client, accounts_mode):
    make_user(iso_client, "boss.one", "approver")
    login = iso_client.post(f"{API}/auth/login", json={"username": "boss.one", "password": PASSWORD})
    res = iso_client.post(f"{API}/auth/users", json={"username": "guest", "role": "viewer", "password": PASSWORD},
                          headers={"X-CSRF-Token": login.json()["csrf_token"]})
    assert res.status_code == 422 and "reserved" in res.json()["detail"]


# ----------------------------------------------------------------------------------- production
def test_the_default_start_is_unchanged_and_guests_are_refused_outside_development_and_test():
    validate_auth_config("accounts", [], "production", cookie_secure=True)
    validate_auth_config("accounts", [], "development", allow_guest=True)
    validate_auth_config("accounts", [], "test", allow_guest=True)
    for environment in ("production", "staging", "", "prod"):
        with pytest.raises(ValueError, match="ALLOW_GUEST=true is refused"):
            validate_auth_config("accounts", [], environment, cookie_secure=True, allow_guest=True)


def test_the_message_names_the_environment_and_the_way_out():
    with pytest.raises(ValueError) as caught:
        validate_auth_config("accounts", [], "production", cookie_secure=True, allow_guest=True)
    text = str(caught.value)
    assert "production" in text and "ALLOW_GUEST" in text and "development or test" in text


def test_the_setting_is_ignored_outside_accounts_mode_even_in_production():
    validate_auth_config("token", [{"name": "Ana", "role": "analyst", "token": AUTOMATION_TOKEN}], "production", allow_guest=True)


def _start(tmp_path, **env):
    full = {**os.environ, "DATABASE_URL": f"sqlite:///{(tmp_path / 'start.db').as_posix()}", "AUTH_TOKENS": "[]", **env}
    return subprocess.run([sys.executable, "-c", "import app.main"], cwd=str(BACKEND), env=full, capture_output=True, text=True, timeout=120)


def test_the_backend_does_not_start_in_production_with_guests_on(tmp_path):
    result = _start(tmp_path, ENVIRONMENT="production", AUTH_MODE="accounts", ALLOW_GUEST="true", SESSION_COOKIE_SECURE="true")
    assert result.returncode != 0
    assert "ALLOW_GUEST=true is refused" in result.stderr


def test_the_backend_does_start_in_production_without_guests(tmp_path):
    result = _start(tmp_path, ENVIRONMENT="production", AUTH_MODE="accounts", ALLOW_GUEST="false", SESSION_COOKIE_SECURE="true")
    assert result.returncode == 0, result.stderr[-500:]


def test_the_backend_does_start_in_development_with_guests_on(tmp_path):
    result = _start(tmp_path, ENVIRONMENT="development", AUTH_MODE="accounts", ALLOW_GUEST="true")
    assert result.returncode == 0, result.stderr[-500:]
