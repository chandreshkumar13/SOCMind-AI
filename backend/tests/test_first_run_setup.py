"""First-run setup in AUTH_MODE=accounts: with no account at all, the page can create the first administrator.

Covers what /auth/status says, that setup signs the new approver in exactly as /auth/login does, that it works once and answers 409
for good afterwards (even when the only accounts are disabled), the audit entries, 404 in the other modes, bad input (422, never
repeating the password), the race between two simultaneous requests, and that no password or hash is ever returned or recorded.
Each test uses its own temporary database (conftest's iso_client). Hashing takes about half a second, so tests create few accounts.
"""
import json
import threading

import pytest

from app.core.config import settings
from app.models.auth_models import AuthSession, UserAccount
from app.services import accounts

API = "/api/v1"
PASSWORD = "a long enough passphrase"
OTHER_PASSWORD = "another long passphrase"


@pytest.fixture
def accounts_mode(monkeypatch):
    monkeypatch.setattr(settings, "AUTH_MODE", "accounts")
    monkeypatch.setattr(settings, "AUTH_TOKENS", [])
    monkeypatch.setattr(settings, "ALLOW_GUEST", False)
    yield


def setup_body(username="first.admin", password=PASSWORD, confirm=None):
    return {"username": username, "password": password, "confirm": password if confirm is None else confirm}


def all_accounts(client):
    db = client.session_factory()
    try:
        return db.query(UserAccount).order_by(UserAccount.id).all()
    finally:
        db.close()


def audit_rows(client, **params):
    res = client.get(f"{API}/audit-logs", params={"limit": 200, **params})
    assert res.status_code == 200, res.text
    return res.json()


# ----------------------------------------------------------------------------------- /auth/status
def test_status_asks_for_setup_only_while_no_account_exists(iso_client, accounts_mode):
    assert iso_client.get(f"{API}/auth/status").json()["setup_required"] is True
    db = iso_client.session_factory()
    try:
        accounts.create_user(db, "ana.analyst", "analyst", PASSWORD)
    finally:
        db.close()
    assert iso_client.get(f"{API}/auth/status").json()["setup_required"] is False


def test_a_database_with_only_disabled_accounts_is_not_open_for_setup(iso_client, accounts_mode):
    """Setup must never be a way to take over an installation that already has accounts, so a disabled account closes it for good.
    Recovery is the command line (enable-user), which the page says."""
    db = iso_client.session_factory()
    try:
        accounts.create_user(db, "old.boss", "approver", PASSWORD)
        accounts.set_active(db, "old.boss", False)
    finally:
        db.close()
    assert iso_client.get(f"{API}/auth/status").json()["setup_required"] is False
    res = iso_client.post(f"{API}/auth/setup", json=setup_body())
    assert res.status_code == 409
    assert [u.username for u in all_accounts(iso_client)] == ["old.boss"]


@pytest.mark.parametrize("mode", ["disabled", "token"])
def test_the_other_modes_never_ask_for_setup(iso_client, monkeypatch, mode):
    monkeypatch.setattr(settings, "AUTH_MODE", mode)
    monkeypatch.setattr(settings, "AUTH_TOKENS", [{"name": "Ana", "role": "analyst", "token": "analyst-token-0123456789abcdef"}] if mode == "token" else [])
    body = iso_client.get(f"{API}/auth/status").json()
    assert body["setup_required"] is False and body["guest_allowed"] is False


@pytest.mark.parametrize("mode", ["disabled", "token"])
def test_setup_does_not_exist_outside_accounts_mode(iso_client, monkeypatch, mode):
    monkeypatch.setattr(settings, "AUTH_MODE", mode)
    monkeypatch.setattr(settings, "AUTH_TOKENS", [{"name": "Ana", "role": "analyst", "token": "analyst-token-0123456789abcdef"}] if mode == "token" else [])
    assert iso_client.post(f"{API}/auth/setup", json=setup_body()).status_code == 404
    assert iso_client.post(f"{API}/auth/setup", json={}).status_code == 404, "404 whatever is sent"
    assert all_accounts(iso_client) == []


# ----------------------------------------------------------------------------------- the happy path
def test_setup_creates_the_first_approver_and_signs_them_in(iso_client, accounts_mode):
    res = iso_client.post(f"{API}/auth/setup", json=setup_body("First.Admin"))
    assert res.status_code == 200, res.text
    body = res.json()
    assert body["authenticated"] is True and body["mode"] == "accounts"
    assert body["name"] == "first.admin" and body["role"] == "approver"
    assert body["csrf_token"] and body["idle_timeout_minutes"] == settings.SESSION_IDLE_MINUTES
    assert body["expires_in_seconds"] > 0 and "guest" not in body
    users = all_accounts(iso_client)
    assert [(u.username, u.role, bool(u.is_active)) for u in users] == [("first.admin", "approver", True)]
    assert users[0].password_hash.startswith("scrypt$") and PASSWORD not in users[0].password_hash


def test_the_cookie_and_csrf_token_work_like_those_of_a_normal_sign_in(iso_client, accounts_mode):
    res = iso_client.post(f"{API}/auth/setup", json=setup_body())
    cookie = res.headers["set-cookie"].lower()
    assert "httponly" in cookie and "samesite=strict" in cookie and f"{accounts.SESSION_COOKIE}=" in cookie
    csrf = {"X-CSRF-Token": res.json()["csrf_token"]}
    me = iso_client.get(f"{API}/auth/me").json()
    assert me["authenticated"] and me["name"] == "first.admin" and me["role"] == "approver" and me["csrf_token"] == csrf["X-CSRF-Token"]
    assert iso_client.get(f"{API}/auth/users").json()[0]["username"] == "first.admin"
    # an approver session may write: it can create the next account, with the CSRF header and not without it
    new = {"username": "ana.analyst", "role": "analyst", "password": OTHER_PASSWORD}
    assert iso_client.post(f"{API}/auth/users", json=new).status_code == 403
    assert iso_client.post(f"{API}/auth/users", json=new, headers=csrf).status_code == 201
    # and the same password signs in again later, as for any account
    again = iso_client.post(f"{API}/auth/login", json={"username": "first.admin", "password": PASSWORD})
    assert again.status_code == 200


def test_setup_is_audited_without_any_password(iso_client, accounts_mode):
    iso_client.post(f"{API}/auth/setup", json=setup_body())
    created = audit_rows(iso_client, action="ACCOUNT_CREATED")
    assert len(created) == 1
    assert created[0]["actor"] == "first.admin" and created[0]["target_id"] == "first.admin"
    assert created[0]["details"] == {"via": "first_run_setup"}
    login = audit_rows(iso_client, action="LOGIN")
    assert len(login) == 1 and login[0]["actor"] == "first.admin"
    assert PASSWORD not in json.dumps(audit_rows(iso_client))


def test_the_response_holds_no_password_and_no_hash(iso_client, accounts_mode):
    res = iso_client.post(f"{API}/auth/setup", json=setup_body())
    stored_hash = all_accounts(iso_client)[0].password_hash
    assert PASSWORD not in res.text and stored_hash not in res.text and "scrypt" not in res.text
    assert "password" not in res.json()


# ----------------------------------------------------------------------------------- once only
def test_setup_works_once_and_answers_409_afterwards(iso_client, accounts_mode):
    assert iso_client.post(f"{API}/auth/setup", json=setup_body()).status_code == 200
    second = iso_client.post(f"{API}/auth/setup", json=setup_body("someone.else", OTHER_PASSWORD))
    assert second.status_code == 409 and second.json()["detail"] == "Setup is already complete."
    assert [u.username for u in all_accounts(iso_client)] == ["first.admin"]
    assert iso_client.get(f"{API}/auth/status").json()["setup_required"] is False


def test_after_setup_it_is_409_even_for_a_badly_formed_request(iso_client, accounts_mode):
    """The 409 comes before the body is looked at, so a closed setup reveals nothing about what is checked."""
    iso_client.post(f"{API}/auth/setup", json=setup_body())
    for payload in ({}, {"username": "x"}, setup_body("x", "short")):
        assert iso_client.post(f"{API}/auth/setup", json=payload).status_code == 409


def test_setup_creates_no_session_and_no_account_when_it_is_refused(iso_client, accounts_mode):
    iso_client.post(f"{API}/auth/setup", json=setup_body())
    db = iso_client.session_factory()
    try:
        sessions_before = db.query(AuthSession).count()
    finally:
        db.close()
    from fastapi.testclient import TestClient
    from app.main import app
    stranger = TestClient(app, raise_server_exceptions=False)
    res = stranger.post(f"{API}/auth/setup", json=setup_body("intruder", OTHER_PASSWORD))
    assert res.status_code == 409 and "set-cookie" not in res.headers
    assert stranger.get(f"{API}/auth/me").status_code == 401
    db = iso_client.session_factory()
    try:
        assert db.query(AuthSession).count() == sessions_before
    finally:
        db.close()


# ----------------------------------------------------------------------------------- bad input
@pytest.mark.parametrize("payload, fragment", [
    (setup_body("x"), "username is 3 to 64"),
    (setup_body("first.admin", "short"), "at least"),
    (setup_body("first.admin", PASSWORD, OTHER_PASSWORD), "do not match"),
    (setup_body("guest"), "reserved"),
])
def test_bad_input_is_422_and_creates_nothing(iso_client, accounts_mode, payload, fragment):
    res = iso_client.post(f"{API}/auth/setup", json=payload)
    assert res.status_code == 422, res.text
    assert fragment in res.json()["detail"]
    assert payload["password"] not in res.text, "an error never repeats the password"
    assert all_accounts(iso_client) == []
    assert iso_client.get(f"{API}/auth/status").json()["setup_required"] is True, "a failed attempt leaves setup open"


def test_a_missing_field_is_422_and_does_not_echo_what_was_sent(iso_client, accounts_mode):
    res = iso_client.post(f"{API}/auth/setup", json={"username": "first.admin", "password": PASSWORD})
    assert res.status_code == 422
    assert PASSWORD not in res.text and "input" not in res.text.replace("input_", "")
    assert all_accounts(iso_client) == []


def test_a_form_post_cannot_set_up_the_first_account(iso_client, accounts_mode):
    res = iso_client.post(f"{API}/auth/setup", data=setup_body())
    assert res.status_code in (415, 422)
    assert all_accounts(iso_client) == []


# ----------------------------------------------------------------------------------- the race
def test_two_simultaneous_setups_create_exactly_one_account(iso_client, accounts_mode):
    """Both requests pass the cheap "is it open" check and hash their password in parallel; the single INSERT ... WHERE NOT EXISTS
    statement then lets exactly one of them in."""
    barrier = threading.Barrier(2)
    outcomes = []

    def attempt(username):
        db = iso_client.session_factory()
        try:
            barrier.wait()
            try:
                accounts.create_first_approver(db, username, PASSWORD)
                outcomes.append("created")
            except accounts.SetupClosed:
                outcomes.append("closed")
        finally:
            db.close()

    threads = [threading.Thread(target=attempt, args=(name,)) for name in ("admin.one", "admin.two")]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(30)
    assert sorted(outcomes) == ["closed", "created"]
    assert len(all_accounts(iso_client)) == 1


def test_the_insert_itself_refuses_when_an_account_appeared_after_the_check(iso_client, accounts_mode, monkeypatch):
    """The "is it open" check can be stale (another process created the account a moment ago). The statement still refuses."""
    db = iso_client.session_factory()
    try:
        accounts.create_user(db, "already.here", "viewer", PASSWORD)
        monkeypatch.setattr(accounts, "setup_required", lambda session: True)      # the stale answer
        with pytest.raises(accounts.SetupClosed):
            accounts.create_first_approver(db, "late.admin", PASSWORD)
    finally:
        db.close()
    assert [u.username for u in all_accounts(iso_client)] == ["already.here"]


def test_the_service_creates_an_approver_and_refuses_bad_input(iso_client, accounts_mode):
    db = iso_client.session_factory()
    try:
        with pytest.raises(ValueError):
            accounts.create_first_approver(db, "x", PASSWORD)
        with pytest.raises(ValueError):
            accounts.create_first_approver(db, "first.admin", "short")
        user = accounts.create_first_approver(db, "first.admin", PASSWORD)
        assert user.role == "approver" and user.is_active
        with pytest.raises(accounts.SetupClosed):
            accounts.create_first_approver(db, "second.admin", PASSWORD)
    finally:
        db.close()
