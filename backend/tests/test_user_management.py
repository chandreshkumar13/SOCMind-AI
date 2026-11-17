"""Account management in AUTH_MODE=accounts: an approver lists, creates, disables and enables accounts through the API.

Covers the roles (only an approver), CSRF, duplicate and invalid input, the two safety rules for disabling (not yourself, never the
last active approver), the end of a disabled account's sessions, the audit entries, the "Authentication events" audit filter, and
that no password and no password hash is ever returned, logged or written to the audit log. Each test uses its own temporary
database (conftest's iso_client). Hashing a password takes about half a second, so the tests create as few accounts as they can.
"""
import json

import pytest
from fastapi.testclient import TestClient

from app.core.config import settings
from app.main import app
from app.models.auth_models import UserAccount
from app.services import accounts

API = "/api/v1"
PASSWORD = "a long enough passphrase"
NEW_PASSWORD = "another long passphrase"
AUTOMATION_TOKEN = "automation-token-0123456789abcdef"


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
    """A second browser: its own cookie jar, the same application and database."""
    return TestClient(app, raise_server_exceptions=False)


def sign_in(client, username, password=PASSWORD):
    res = client.post(f"{API}/auth/login", json={"username": username, "password": password})
    assert res.status_code == 200, res.text
    return {"X-CSRF-Token": res.json()["csrf_token"]}


def approver_session(client, username="boss.one"):
    make_user(client, username, "approver")
    return sign_in(client, username)


def audit_rows(client, **params):
    res = client.get(f"{API}/audit-logs", params={"limit": 200, **params})
    assert res.status_code == 200, res.text
    return res.json()


def account_rows(client):
    db = client.session_factory()
    try:
        return {u.username: u for u in db.query(UserAccount).all()}
    finally:
        db.close()


# ----------------------------------------------------------------------------------- who may manage accounts
@pytest.mark.parametrize("role", ["viewer", "analyst"])
def test_only_an_approver_may_manage_accounts(iso_client, accounts_mode, role):
    make_user(iso_client, f"{role}.person", role)
    headers = sign_in(iso_client, f"{role}.person")
    calls = [
        ("get", "/auth/users", None),
        ("post", "/auth/users", {"username": "new.person", "role": "viewer", "password": PASSWORD}),
        ("post", f"/auth/users/{role}.person/disable", None),
        ("post", f"/auth/users/{role}.person/enable", None),
    ]
    for method, path, body in calls:
        res = iso_client.request(method, f"{API}{path}", headers=headers, json=body)
        assert res.status_code == 403, (role, method, path, res.status_code)
    assert set(account_rows(iso_client)) == {f"{role}.person"}, "a refused request must not create or change an account"


def test_without_a_session_every_account_route_is_refused_and_there_is_no_public_sign_up(iso_client, accounts_mode):
    for method, path in (("get", "/auth/users"), ("post", "/auth/users"), ("post", "/auth/users/x/disable"),
                         ("post", "/auth/users/x/enable"), ("post", "/auth/password")):
        assert iso_client.request(method, f"{API}{path}").status_code == 401, (method, path)
    res = iso_client.post(f"{API}/auth/users", json={"username": "stranger", "role": "approver", "password": PASSWORD})
    assert res.status_code == 401
    assert account_rows(iso_client) == {}
    for path in ("/auth/register", "/auth/signup", "/auth/sign-up"):
        assert iso_client.post(f"{API}{path}", json={}).status_code in (404, 405), path


def test_a_write_with_the_cookie_but_without_the_csrf_token_is_refused(iso_client, accounts_mode):
    approver_session(iso_client)
    res = iso_client.post(f"{API}/auth/users", json={"username": "new.person", "role": "viewer", "password": PASSWORD})
    assert res.status_code == 403 and "CSRF" in res.json()["detail"]
    assert set(account_rows(iso_client)) == {"boss.one"}
    assert iso_client.post(f"{API}/auth/users/boss.one/disable").status_code == 403


@pytest.mark.parametrize("mode", ["disabled", "token"])
def test_the_account_routes_do_not_exist_outside_accounts_mode(iso_client, monkeypatch, mode):
    monkeypatch.setattr(settings, "AUTH_MODE", mode)
    monkeypatch.setattr(settings, "AUTH_TOKENS", [{"name": "Boss", "role": "approver", "token": AUTOMATION_TOKEN}] if mode == "token" else [])
    headers = {"Authorization": f"Bearer {AUTOMATION_TOKEN}"} if mode == "token" else {}
    assert iso_client.get(f"{API}/auth/users", headers=headers).status_code == 404
    res = iso_client.post(f"{API}/auth/users", headers=headers, json={"username": "new.person", "role": "viewer", "password": PASSWORD})
    assert res.status_code == 404
    assert iso_client.post(f"{API}/auth/users/x/disable", headers=headers).status_code == 404
    assert iso_client.post(f"{API}/auth/password", headers=headers, json={"current_password": "x", "new_password": "y"}).status_code == 404


# ----------------------------------------------------------------------------------- listing and creating
def test_the_list_shows_username_role_state_and_creation_time_and_never_a_password_or_hash(iso_client, accounts_mode):
    headers = approver_session(iso_client)
    created = iso_client.post(f"{API}/auth/users", headers=headers, json={"username": "ana.analyst", "role": "analyst", "password": NEW_PASSWORD})
    assert created.status_code == 201
    listing = iso_client.get(f"{API}/auth/users")
    assert listing.status_code == 200
    users = {u["username"]: u for u in listing.json()}
    assert set(users) == {"boss.one", "ana.analyst"}
    for record in users.values():
        assert set(record) == {"username", "role", "is_active", "created_at"}
        assert record["created_at"].endswith("Z") and record["is_active"] is True
    assert users["ana.analyst"]["role"] == "analyst"
    for text in (listing.text, created.text):
        assert "scrypt$" not in text and "password" not in text.lower() and PASSWORD not in text and NEW_PASSWORD not in text


def test_an_approver_creates_an_account_that_can_then_sign_in_and_the_audit_log_records_it_without_the_password(iso_client, accounts_mode):
    headers = approver_session(iso_client)
    res = iso_client.post(f"{API}/auth/users", headers=headers, json={"username": "  Ana.Analyst ", "role": "analyst", "password": NEW_PASSWORD})
    assert res.status_code == 201
    assert res.json()["username"] == "ana.analyst", "the username is stored trimmed and in lower case"
    assert res.json()["role"] == "analyst" and res.json()["is_active"] is True

    row = account_rows(iso_client)["ana.analyst"]
    assert row.password_hash.startswith("scrypt$") and NEW_PASSWORD not in row.password_hash

    fresh = another_client()
    assert fresh.post(f"{API}/auth/login", json={"username": "ana.analyst", "password": NEW_PASSWORD}).status_code == 200
    assert fresh.get(f"{API}/auth/me").json()["role"] == "analyst"

    entries = audit_rows(iso_client, action="ACCOUNT_CREATED")
    assert len(entries) == 1
    entry = entries[0]
    assert entry["actor"] == "boss.one" and entry["target_id"] == "ana.analyst" and entry["details"] == {"role": "analyst"}
    assert NEW_PASSWORD not in json.dumps(audit_rows(iso_client)), "no password anywhere in the audit log"


def test_a_duplicate_username_is_a_409_with_a_clear_message_and_creates_nothing(iso_client, accounts_mode):
    headers = approver_session(iso_client)
    assert iso_client.post(f"{API}/auth/users", headers=headers, json={"username": "ana.analyst", "role": "viewer", "password": PASSWORD}).status_code == 201
    for spelling in ("ana.analyst", "ANA.ANALYST", " Ana.Analyst "):
        res = iso_client.post(f"{API}/auth/users", headers=headers, json={"username": spelling, "role": "viewer", "password": PASSWORD})
        assert res.status_code == 409 and res.json()["detail"] == "That username already exists.", spelling
    assert len(account_rows(iso_client)) == 2
    assert len(audit_rows(iso_client, action="ACCOUNT_CREATED")) == 1


@pytest.mark.parametrize("body,needle", [
    ({"username": "new.person", "role": "viewer", "password": "short"}, "at least 12 characters"),
    ({"username": "new.person", "role": "viewer", "password": " " * 20}, "only spaces"),
    ({"username": "new.person", "role": "viewer", "password": "x" * 1025}, "at most 1024"),
    ({"username": "new.person", "role": "root", "password": PASSWORD}, "role must be one of"),
    ({"username": "x", "role": "viewer", "password": PASSWORD}, "3 to 64 characters"),
    ({"username": "has space", "role": "viewer", "password": PASSWORD}, "3 to 64 characters"),
])
def test_an_invalid_role_username_or_password_is_a_422_with_a_clear_message_that_never_repeats_the_password(iso_client, accounts_mode, body, needle):
    headers = approver_session(iso_client)
    res = iso_client.post(f"{API}/auth/users", headers=headers, json=body)
    assert res.status_code == 422, res.text
    assert needle in res.json()["detail"]
    assert body["password"].strip() == "" or body["password"] not in res.text
    assert set(account_rows(iso_client)) == {"boss.one"}


def test_a_validation_error_on_an_auth_route_never_sends_the_submitted_password_back(iso_client, accounts_mode):
    """FastAPI's default 422 repeats the whole request body when a field is missing. For /auth/... that body holds a password."""
    headers = approver_session(iso_client)
    secret = "a secret passphrase nobody may see"
    for body in ({"role": "viewer", "password": secret}, {"username": "new.person", "password": secret},
                 {"username": "new.person", "role": "viewer", "password": secret, "unexpected": [secret]}):
        res = iso_client.post(f"{API}/auth/users", headers=headers, json=body)
        if res.status_code == 201:
            continue                                  # extra fields are ignored, so the last body is a valid request
        assert res.status_code == 422
        assert secret not in res.text
        assert all("input" not in error for error in res.json()["detail"])
    too_long = iso_client.post(f"{API}/auth/users", headers=headers, json={"username": "new.person", "role": "viewer", "password": "p" * 3000})
    assert too_long.status_code == 422 and "pppppppp" not in too_long.text
    login = iso_client.post(f"{API}/auth/login", json={"username": "ana", "password": secret * 100})
    assert login.status_code == 422 and secret not in login.text


def test_other_routes_keep_the_default_validation_answer(iso_client, accounts_mode):
    headers = approver_session(iso_client)
    res = iso_client.post(f"{API}/alerts", headers=headers, json={"id": ["not", "text"]})
    assert res.status_code == 422 and isinstance(res.json()["detail"], list) and res.json()["detail"]


# ----------------------------------------------------------------------------------- disabling and enabling
def test_disabling_an_account_ends_its_sessions_refuses_its_sign_in_and_is_audited(iso_client, accounts_mode):
    headers = approver_session(iso_client)
    make_user(iso_client, "ana.analyst", "analyst")
    ana = another_client()
    sign_in(ana, "ana.analyst")
    assert ana.get(f"{API}/alerts").status_code == 200

    res = iso_client.post(f"{API}/auth/users/ana.analyst/disable", headers=headers)
    assert res.status_code == 200 and res.json()["is_active"] is False and res.json()["username"] == "ana.analyst"
    assert ana.get(f"{API}/alerts").status_code == 401, "an open session ends on the next request"
    refused = another_client().post(f"{API}/auth/login", json={"username": "ana.analyst", "password": PASSWORD})
    assert refused.status_code == 401 and refused.json()["detail"] == "Invalid username or password."

    entries = audit_rows(iso_client, action="ACCOUNT_DISABLED")
    assert len(entries) == 1
    assert entries[0]["actor"] == "boss.one" and entries[0]["target_id"] == "ana.analyst" and entries[0]["details"] == {"sessions_ended": 1}


def test_enabling_an_account_lets_it_sign_in_again_and_asking_for_the_current_state_changes_nothing(iso_client, accounts_mode):
    headers = approver_session(iso_client)
    make_user(iso_client, "ana.analyst", "analyst")
    assert iso_client.post(f"{API}/auth/users/ana.analyst/disable", headers=headers).status_code == 200
    again = iso_client.post(f"{API}/auth/users/ana.analyst/disable", headers=headers)
    assert again.status_code == 200 and again.json()["is_active"] is False
    assert len(audit_rows(iso_client, action="ACCOUNT_DISABLED")) == 1, "no second entry when nothing changed"

    enabled = iso_client.post(f"{API}/auth/users/ana.analyst/enable", headers=headers)
    assert enabled.status_code == 200 and enabled.json()["is_active"] is True
    assert iso_client.post(f"{API}/auth/users/ana.analyst/enable", headers=headers).status_code == 200
    entries = audit_rows(iso_client, action="ACCOUNT_ENABLED")
    assert len(entries) == 1 and entries[0]["actor"] == "boss.one" and entries[0]["target_id"] == "ana.analyst"
    assert another_client().post(f"{API}/auth/login", json={"username": "ana.analyst", "password": PASSWORD}).status_code == 200


def test_an_unknown_username_is_a_404(iso_client, accounts_mode):
    headers = approver_session(iso_client)
    for action in ("disable", "enable"):
        res = iso_client.post(f"{API}/auth/users/no.such.user/{action}", headers=headers)
        assert res.status_code == 404 and res.json()["detail"] == "No account has that username."
    assert iso_client.post(f"{API}/auth/users/!!/disable", headers=headers).status_code == 404


def test_an_approver_cannot_disable_their_own_account(iso_client, accounts_mode):
    headers = approver_session(iso_client, "boss.one")
    make_user(iso_client, "boss.two", "approver")
    res = iso_client.post(f"{API}/auth/users/boss.one/disable", headers=headers)
    assert res.status_code == 409 and res.json()["detail"] == "You cannot disable your own account."
    assert account_rows(iso_client)["boss.one"].is_active is True
    assert iso_client.get(f"{API}/auth/users").status_code == 200, "the session is still open"
    assert audit_rows(iso_client, action="ACCOUNT_DISABLED") == []
    # another approver may still be disabled, because this one stays active
    assert iso_client.post(f"{API}/auth/users/boss.two/disable", headers=headers).status_code == 200


def test_the_last_active_approver_cannot_be_disabled_even_by_a_static_token(iso_client, accounts_mode, monkeypatch):
    """A static token has no account, so "yourself" does not apply to it; the last-approver rule is what protects the system."""
    monkeypatch.setattr(settings, "AUTH_TOKENS", [{"name": "Automation", "role": "approver", "token": AUTOMATION_TOKEN}])
    token = {"Authorization": f"Bearer {AUTOMATION_TOKEN}"}
    make_user(iso_client, "boss.one", "approver")
    make_user(iso_client, "boss.two", "approver")
    make_user(iso_client, "ana.analyst", "analyst")

    assert iso_client.post(f"{API}/auth/users/boss.one/disable", headers=token).status_code == 200
    last = iso_client.post(f"{API}/auth/users/boss.two/disable", headers=token)
    assert last.status_code == 409 and "last active approver" in last.json()["detail"]
    assert account_rows(iso_client)["boss.two"].is_active is True
    assert another_client().post(f"{API}/auth/login", json={"username": "boss.two", "password": PASSWORD}).status_code == 200

    # a non-approver is not protected by this rule, and a disabled approver can be enabled again
    assert iso_client.post(f"{API}/auth/users/ana.analyst/disable", headers=token).status_code == 200
    assert iso_client.post(f"{API}/auth/users/boss.one/enable", headers=token).status_code == 200
    assert iso_client.post(f"{API}/auth/users/boss.two/disable", headers=token).status_code == 200


def test_the_account_service_enforces_the_same_rules_without_the_api(iso_client, accounts_mode):
    make_user(iso_client, "boss.one", "approver")
    make_user(iso_client, "ana.analyst", "analyst")
    db = iso_client.session_factory()
    try:
        with pytest.raises(accounts.AccountRuleError):
            accounts.change_active(db, None, "boss.one", False)
        with pytest.raises(accounts.AccountRuleError):
            accounts.change_active(db, "ana.analyst", "ana.analyst", False)
        with pytest.raises(ValueError):
            accounts.change_active(db, None, "nobody.here", False)
        user, ended, changed = accounts.change_active(db, "boss.one", "ana.analyst", False)
        assert (user.is_active, ended, changed) == (False, 0, True)
        assert accounts.change_active(db, "boss.one", "ana.analyst", False)[2] is False
    finally:
        db.close()


# ----------------------------------------------------------------------------------- the "Authentication events" audit filter
def test_the_authentication_category_returns_only_sign_in_and_account_events(iso_client, accounts_mode):
    headers = approver_session(iso_client)
    assert iso_client.post(f"{API}/alerts/seed", headers=headers).status_code == 200            # a non-authentication event
    iso_client.post(f"{API}/auth/users", headers=headers, json={"username": "ana.analyst", "role": "viewer", "password": PASSWORD})
    iso_client.post(f"{API}/auth/users/ana.analyst/disable", headers=headers)
    iso_client.post(f"{API}/auth/users/ana.analyst/enable", headers=headers)
    another_client().post(f"{API}/auth/login", json={"username": "ana.analyst", "password": "wrong-wrong-wrong"})

    everything = {row["action"] for row in audit_rows(iso_client)}
    assert "ALERTS_SEEDED" in everything
    auth_only = audit_rows(iso_client, category="authentication")
    actions = {row["action"] for row in auth_only}
    assert actions == {"LOGIN", "LOGIN_FAILED", "ACCOUNT_CREATED", "ACCOUNT_DISABLED", "ACCOUNT_ENABLED"}, actions
    assert actions <= {"LOGIN", "LOGIN_FAILED", "LOGIN_LOCKED", "LOGOUT", "ACCOUNT_CREATED", "ACCOUNT_DISABLED", "ACCOUNT_ENABLED", "PASSWORD_CHANGED"}
    # the category combines with the other filters
    only_created = audit_rows(iso_client, category="authentication", action="ACCOUNT_CREATED")
    assert [row["action"] for row in only_created] == ["ACCOUNT_CREATED"]
    assert audit_rows(iso_client, category="authentication", action="ALERTS_SEEDED") == []
    assert iso_client.get(f"{API}/audit-logs", params={"category": "everything"}).status_code == 422


def test_logout_and_lockout_events_are_in_the_authentication_category(iso_client, accounts_mode, monkeypatch):
    make_user(iso_client, "ana.analyst", "analyst")
    headers = sign_in(iso_client, "ana.analyst")
    assert iso_client.post(f"{API}/auth/logout", headers=headers).status_code == 200
    stranger = another_client()
    for _ in range(settings.LOGIN_MAX_FAILURES + 1):
        stranger.post(f"{API}/auth/login", json={"username": "ana.analyst", "password": "wrong-wrong-wrong"})
    # the session above has ended, so the log is read with a static viewer token
    monkeypatch.setattr(settings, "AUTH_TOKENS", [{"name": "Reader", "role": "viewer", "token": AUTOMATION_TOKEN}])
    rows = iso_client.get(f"{API}/audit-logs", params={"category": "authentication", "limit": 200},
                          headers={"Authorization": f"Bearer {AUTOMATION_TOKEN}"}).json()
    assert {"LOGIN", "LOGOUT", "LOGIN_FAILED", "LOGIN_LOCKED"} <= {row["action"] for row in rows}
