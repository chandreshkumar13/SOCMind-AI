"""Changing your own password in AUTH_MODE=accounts (POST /auth/password), and the session timing the page needs for its expiry
warning (`expires_in_seconds` on /auth/login and /auth/me).

Covers: the new password works and the old one does not, every other session ends while the current one stays open, a wrong
current password is a 401 that counts towards the sign-in lockout, the new password follows the same rules as a new account, CSRF
and roles, the audit entry, and that no password or hash appears in a response, the log or the audit log. Each test uses its own
temporary database (conftest's iso_client). Hashing takes about half a second, so the tests create as few accounts as they can.
"""
import json

import pytest
from fastapi.testclient import TestClient

from app.core.config import settings
from app.main import app
from app.models.auth_models import AuthSession, UserAccount
from app.services import accounts

API = "/api/v1"
PASSWORD = "a long enough passphrase"
NEW_PASSWORD = "a brand new passphrase"
STATIC_TOKEN = "static-token-for-automation-0123456789"


@pytest.fixture
def accounts_mode(monkeypatch):
    monkeypatch.setattr(settings, "AUTH_MODE", "accounts")
    monkeypatch.setattr(settings, "AUTH_TOKENS", [])
    yield


def make_user(client, username, role, password=PASSWORD):
    db = client.session_factory()
    try:
        return accounts.create_user(db, username, role, password)
    finally:
        db.close()


def another_client():
    return TestClient(app, raise_server_exceptions=False)


def sign_in(client, username, password=PASSWORD):
    res = client.post(f"{API}/auth/login", json={"username": username, "password": password})
    assert res.status_code == 200, res.text
    return {"X-CSRF-Token": res.json()["csrf_token"]}


def change(client, headers, current=PASSWORD, new=NEW_PASSWORD):
    return client.post(f"{API}/auth/password", headers=headers, json={"current_password": current, "new_password": new})


def stored_hash(client, username):
    db = client.session_factory()
    try:
        return db.query(UserAccount).filter(UserAccount.username == username).one().password_hash
    finally:
        db.close()


def can_sign_in(username, password):
    return another_client().post(f"{API}/auth/login", json={"username": username, "password": password}).status_code == 200


# ----------------------------------------------------------------------------------- the change itself
def test_a_password_change_switches_the_password_ends_other_sessions_and_keeps_this_one(iso_client, accounts_mode):
    make_user(iso_client, "ana.analyst", "analyst")
    headers = sign_in(iso_client, "ana.analyst")            # this browser
    other_browser = another_client()
    sign_in(other_browser, "ana.analyst")                   # a second session of the same account
    assert other_browser.get(f"{API}/alerts").status_code == 200
    old_hash = stored_hash(iso_client, "ana.analyst")

    res = change(iso_client, headers)
    assert res.status_code == 200
    assert res.json() == {"status": "ok", "other_sessions_ended": 1}
    assert PASSWORD not in res.text and NEW_PASSWORD not in res.text and "scrypt$" not in res.text

    assert iso_client.get(f"{API}/auth/me").status_code == 200, "the session that made the change stays open"
    assert other_browser.get(f"{API}/alerts").status_code == 401, "every other session ended"
    assert other_browser.get(f"{API}/auth/me").status_code == 401

    new_hash = stored_hash(iso_client, "ana.analyst")
    assert new_hash != old_hash and new_hash.startswith("scrypt$") and NEW_PASSWORD not in new_hash
    assert not can_sign_in("ana.analyst", PASSWORD), "the old password no longer works"
    assert can_sign_in("ana.analyst", NEW_PASSWORD), "the new password works"

    db = iso_client.session_factory()
    try:
        reasons = sorted((row.revoke_reason or "open") for row in db.query(AuthSession).all())
    finally:
        db.close()
    assert "password_changed" in reasons


def test_the_change_is_audited_as_password_changed_without_any_password(iso_client, accounts_mode):
    make_user(iso_client, "ana.analyst", "viewer")           # any role may change its own password
    headers = sign_in(iso_client, "ana.analyst")
    assert change(iso_client, headers).status_code == 200
    rows = iso_client.get(f"{API}/audit-logs", params={"limit": 200}).json()
    entries = [r for r in rows if r["action"] == "PASSWORD_CHANGED"]
    assert len(entries) == 1
    assert entries[0]["actor"] == "ana.analyst" and entries[0]["target_id"] == "ana.analyst"
    assert entries[0]["details"]["other_sessions_ended"] == 0
    everything = json.dumps(rows)
    assert PASSWORD not in everything and NEW_PASSWORD not in everything and "scrypt$" not in everything


def test_a_wrong_current_password_is_a_401_and_changes_nothing(iso_client, accounts_mode):
    make_user(iso_client, "ana.analyst", "analyst")
    headers = sign_in(iso_client, "ana.analyst")
    other_browser = another_client()
    sign_in(other_browser, "ana.analyst")
    before = stored_hash(iso_client, "ana.analyst")

    res = change(iso_client, headers, current="not the current one")
    assert res.status_code == 401 and res.json()["detail"] == "The current password is incorrect."
    assert "not the current one" not in res.text
    assert stored_hash(iso_client, "ana.analyst") == before
    assert other_browser.get(f"{API}/auth/me").status_code == 200, "a refused change ends no session"
    assert iso_client.get(f"{API}/auth/me").status_code == 200
    rows = iso_client.get(f"{API}/audit-logs", params={"limit": 200}).json()
    assert not any(r["action"] == "PASSWORD_CHANGED" for r in rows)


def test_wrong_current_passwords_count_towards_the_sign_in_lockout(iso_client, accounts_mode):
    make_user(iso_client, "ana.analyst", "analyst")
    headers = sign_in(iso_client, "ana.analyst")
    for _ in range(settings.LOGIN_MAX_FAILURES):
        assert change(iso_client, headers, current="wrong wrong wrong").status_code == 401
    locked = change(iso_client, headers)                     # even the right current password is refused now
    assert locked.status_code == 429 and "Too many failed attempts" in locked.json()["detail"]
    assert stored_hash(iso_client, "ana.analyst").startswith("scrypt$") and not can_sign_in("ana.analyst", NEW_PASSWORD)
    # the lock is the sign-in lock for this name and address, so signing in is refused as well
    assert another_client().post(f"{API}/auth/login", json={"username": "ana.analyst", "password": PASSWORD}).status_code == 429


@pytest.mark.parametrize("new,expected", [
    ("short", "at least 12 characters"),
    (" " * 20, "only spaces"),
    ("p" * 1025, "at most 1024"),
    (PASSWORD, "must be different from the current one"),
])
def test_the_new_password_follows_the_same_rules_as_a_new_account(iso_client, accounts_mode, new, expected):
    make_user(iso_client, "ana.analyst", "analyst")
    headers = sign_in(iso_client, "ana.analyst")
    other_browser = another_client()
    sign_in(other_browser, "ana.analyst")
    before = stored_hash(iso_client, "ana.analyst")
    res = change(iso_client, headers, new=new)
    assert res.status_code == 422 and expected in res.json()["detail"], res.text
    assert new.strip() == "" or new == PASSWORD or new not in res.text
    assert stored_hash(iso_client, "ana.analyst") == before
    assert other_browser.get(f"{API}/auth/me").status_code == 200, "a refused change ends no session"
    assert can_sign_in("ana.analyst", PASSWORD)


# ----------------------------------------------------------------------------------- who may call it
def test_the_change_needs_a_session_and_the_csrf_token(iso_client, accounts_mode):
    make_user(iso_client, "ana.analyst", "analyst")
    assert iso_client.post(f"{API}/auth/password", json={"current_password": PASSWORD, "new_password": NEW_PASSWORD}).status_code == 401
    sign_in(iso_client, "ana.analyst")
    no_csrf = iso_client.post(f"{API}/auth/password", json={"current_password": PASSWORD, "new_password": NEW_PASSWORD})
    assert no_csrf.status_code == 403 and "CSRF" in no_csrf.json()["detail"]
    assert can_sign_in("ana.analyst", PASSWORD) and not can_sign_in("ana.analyst", NEW_PASSWORD)


def test_a_static_token_has_no_account_and_cannot_change_a_password(iso_client, accounts_mode, monkeypatch):
    monkeypatch.setattr(settings, "AUTH_TOKENS", [{"name": "Automation", "role": "approver", "token": STATIC_TOKEN}])
    res = iso_client.post(f"{API}/auth/password", headers={"Authorization": f"Bearer {STATIC_TOKEN}"},
                          json={"current_password": PASSWORD, "new_password": NEW_PASSWORD})
    assert res.status_code == 403 and "signed-in account" in res.json()["detail"]


def test_a_validation_error_never_sends_the_submitted_passwords_back(iso_client, accounts_mode):
    make_user(iso_client, "ana.analyst", "analyst")
    headers = sign_in(iso_client, "ana.analyst")
    res = iso_client.post(f"{API}/auth/password", headers=headers, json={"current_password": PASSWORD})
    assert res.status_code == 422
    assert PASSWORD not in res.text and all("input" not in error for error in res.json()["detail"])
    res = iso_client.post(f"{API}/auth/password", headers=headers, json={"current_password": PASSWORD, "new_password": "n" * 3000})
    assert res.status_code == 422 and PASSWORD not in res.text and "nnnnnnnn" not in res.text


def test_a_disabled_account_cannot_change_its_password(iso_client, accounts_mode):
    make_user(iso_client, "ana.analyst", "analyst")
    headers = sign_in(iso_client, "ana.analyst")
    db = iso_client.session_factory()
    try:
        accounts.set_active(db, "ana.analyst", False)
    finally:
        db.close()
    assert change(iso_client, headers).status_code == 401
    assert not can_sign_in("ana.analyst", NEW_PASSWORD)


# ----------------------------------------------------------------------------------- session timing for the expiry warning
def test_sign_in_and_me_report_how_many_seconds_the_session_has_left(iso_client, accounts_mode):
    make_user(iso_client, "ana.analyst", "analyst")
    login = iso_client.post(f"{API}/auth/login", json={"username": "ana.analyst", "password": PASSWORD})
    assert login.status_code == 200
    limit = settings.SESSION_ABSOLUTE_HOURS * 3600
    me = iso_client.get(f"{API}/auth/me").json()
    for body in (login.json(), me):
        assert limit - 60 < body["expires_in_seconds"] <= limit, body["expires_in_seconds"]
        assert body["idle_timeout_minutes"] == settings.SESSION_IDLE_MINUTES
    assert me["expires_in_seconds"] <= login.json()["expires_in_seconds"]


def test_the_other_modes_do_not_report_session_timing(iso_client, monkeypatch):
    monkeypatch.setattr(settings, "AUTH_MODE", "token")
    monkeypatch.setattr(settings, "AUTH_TOKENS", [{"name": "Automation", "role": "viewer", "token": STATIC_TOKEN}])
    me = iso_client.get(f"{API}/auth/me", headers={"Authorization": f"Bearer {STATIC_TOKEN}"}).json()
    assert me == {"mode": "token", "authenticated": True, "name": "Automation", "role": "viewer"}
