"""An approver resets another account's password (POST /auth/users/{username}/password) and the command line does the same.

Covers who may do it (only an approver, with CSRF, in accounts mode), that every session of the account ends, that the old password
stops working and the new one works, that an approver cannot reset their own password this way (409), the password rules, the sign-in
lockout being cleared, the PASSWORD_RESET audit entry, and that no password or hash is ever returned or recorded.
"""
import json

import pytest
from fastapi.testclient import TestClient

from app.cli import accounts as cli
from app.core.config import settings
from app.main import app
from app.models.auth_models import AuthSession, UserAccount
from app.services import accounts

API = "/api/v1"
PASSWORD = "a long enough passphrase"
NEW_PASSWORD = "a brand new passphrase"
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
    return TestClient(app, raise_server_exceptions=False)


def sign_in(client, username, password=PASSWORD):
    res = client.post(f"{API}/auth/login", json={"username": username, "password": password})
    assert res.status_code == 200, res.text
    return {"X-CSRF-Token": res.json()["csrf_token"]}


def approver_session(client, username="boss.one"):
    make_user(client, username, "approver")
    return sign_in(client, username)


def reset(client, headers, username, password=NEW_PASSWORD):
    return client.post(f"{API}/auth/users/{username}/password", json={"new_password": password}, headers=headers)


def audit_rows(client, **params):
    res = client.get(f"{API}/audit-logs", params={"limit": 200, **params})
    assert res.status_code == 200, res.text
    return res.json()


def account(client, username):
    db = client.session_factory()
    try:
        return db.query(UserAccount).filter(UserAccount.username == username).first()
    finally:
        db.close()


# ----------------------------------------------------------------------------------- who may reset
@pytest.mark.parametrize("role", ["viewer", "analyst"])
def test_only_an_approver_may_reset_a_password(iso_client, accounts_mode, role):
    make_user(iso_client, "target.user", "viewer")
    make_user(iso_client, f"{role}.person", role)
    headers = sign_in(iso_client, f"{role}.person")
    res = reset(iso_client, headers, "target.user")
    assert res.status_code == 403
    assert another_client().post(f"{API}/auth/login", json={"username": "target.user", "password": PASSWORD}).status_code == 200


def test_no_session_is_401_and_a_missing_csrf_token_is_403(iso_client, accounts_mode):
    make_user(iso_client, "target.user", "viewer")
    assert another_client().post(f"{API}/auth/users/target.user/password", json={"new_password": NEW_PASSWORD}).status_code == 401
    approver_session(iso_client)
    no_csrf = iso_client.post(f"{API}/auth/users/target.user/password", json={"new_password": NEW_PASSWORD})
    assert no_csrf.status_code == 403
    assert another_client().post(f"{API}/auth/login", json={"username": "target.user", "password": PASSWORD}).status_code == 200


@pytest.mark.parametrize("mode", ["disabled", "token"])
def test_the_route_does_not_exist_outside_accounts_mode(iso_client, monkeypatch, mode):
    monkeypatch.setattr(settings, "AUTH_MODE", mode)
    monkeypatch.setattr(settings, "AUTH_TOKENS", [{"name": "Boss", "role": "approver", "token": AUTOMATION_TOKEN}] if mode == "token" else [])
    headers = {"Authorization": f"Bearer {AUTOMATION_TOKEN}"} if mode == "token" else {}
    res = iso_client.post(f"{API}/auth/users/anyone/password", json={"new_password": NEW_PASSWORD}, headers=headers)
    assert res.status_code == 404


# ----------------------------------------------------------------------------------- the reset itself
def test_a_reset_ends_every_session_of_that_account_and_swaps_the_password(iso_client, accounts_mode):
    approver = approver_session(iso_client)
    make_user(iso_client, "ana.analyst", "analyst")
    first, second = another_client(), another_client()
    sign_in(first, "ana.analyst")
    sign_in(second, "ana.analyst")
    assert first.get(f"{API}/alerts").status_code == 200 and second.get(f"{API}/alerts").status_code == 200

    res = reset(iso_client, approver, "ana.analyst")
    assert res.status_code == 200, res.text
    assert res.json() == {"status": "ok", "sessions_ended": 2}

    assert first.get(f"{API}/alerts").status_code == 401 and second.get(f"{API}/alerts").status_code == 401
    assert another_client().post(f"{API}/auth/login", json={"username": "ana.analyst", "password": PASSWORD}).status_code == 401
    assert another_client().post(f"{API}/auth/login", json={"username": "ana.analyst", "password": NEW_PASSWORD}).status_code == 200
    assert iso_client.get(f"{API}/auth/me").json()["name"] == "boss.one", "the approver's own session is untouched"

    db = iso_client.session_factory()
    try:
        reasons = [row.revoke_reason for row in db.query(AuthSession).join(UserAccount).filter(UserAccount.username == "ana.analyst")]
    finally:
        db.close()
    assert reasons.count("password_reset") == 2


def test_the_reset_is_audited_with_the_approver_as_actor_and_no_password(iso_client, accounts_mode):
    approver = approver_session(iso_client)
    make_user(iso_client, "ana.analyst", "analyst")
    reset(iso_client, approver, "ana.analyst")
    rows = audit_rows(iso_client, action="PASSWORD_RESET")
    assert len(rows) == 1
    assert rows[0]["actor"] == "boss.one" and rows[0]["target_id"] == "ana.analyst" and rows[0]["details"] == {"sessions_ended": 0}
    everything = json.dumps(audit_rows(iso_client))
    assert PASSWORD not in everything and NEW_PASSWORD not in everything
    assert account(iso_client, "ana.analyst").password_hash not in everything


def test_the_reset_shows_under_authentication_events(iso_client, accounts_mode):
    approver = approver_session(iso_client)
    make_user(iso_client, "ana.analyst", "analyst")
    reset(iso_client, approver, "ana.analyst")
    actions = {row["action"] for row in audit_rows(iso_client, category="authentication")}
    assert "PASSWORD_RESET" in actions


def test_the_response_holds_no_password_and_no_hash(iso_client, accounts_mode):
    approver = approver_session(iso_client)
    make_user(iso_client, "ana.analyst", "analyst")
    res = reset(iso_client, approver, "ana.analyst")
    stored = account(iso_client, "ana.analyst").password_hash
    assert NEW_PASSWORD not in res.text and PASSWORD not in res.text and stored not in res.text and "scrypt" not in res.text
    assert stored.startswith("scrypt$") and NEW_PASSWORD not in stored


def test_a_disabled_account_can_be_reset_and_stays_disabled(iso_client, accounts_mode):
    approver = approver_session(iso_client)
    make_user(iso_client, "ana.analyst", "analyst")
    db = iso_client.session_factory()
    try:
        accounts.set_active(db, "ana.analyst", False)
    finally:
        db.close()
    assert reset(iso_client, approver, "ana.analyst").status_code == 200
    assert account(iso_client, "ana.analyst").is_active is False
    assert another_client().post(f"{API}/auth/login", json={"username": "ana.analyst", "password": NEW_PASSWORD}).status_code == 401


def test_a_reset_clears_the_sign_in_lockout_so_the_new_password_works_at_once(iso_client, accounts_mode, monkeypatch):
    monkeypatch.setattr(settings, "LOGIN_MAX_FAILURES", 2)
    approver = approver_session(iso_client)
    make_user(iso_client, "ana.analyst", "analyst")
    stranger = another_client()
    for _ in range(2):
        assert stranger.post(f"{API}/auth/login", json={"username": "ana.analyst", "password": "wrong password here"}).status_code == 401
    assert stranger.post(f"{API}/auth/login", json={"username": "ana.analyst", "password": PASSWORD}).status_code == 429
    reset(iso_client, approver, "ana.analyst")
    assert stranger.post(f"{API}/auth/login", json={"username": "ana.analyst", "password": NEW_PASSWORD}).status_code == 200


# ----------------------------------------------------------------------------------- the rules
def test_an_approver_cannot_reset_their_own_password_here(iso_client, accounts_mode):
    approver = approver_session(iso_client)
    res = reset(iso_client, approver, "boss.one")
    assert res.status_code == 409 and "Change password" in res.json()["detail"]
    assert another_client().post(f"{API}/auth/login", json={"username": "boss.one", "password": PASSWORD}).status_code == 200
    assert audit_rows(iso_client, action="PASSWORD_RESET") == []


def test_the_username_is_matched_after_normalising_so_the_self_rule_cannot_be_dodged(iso_client, accounts_mode):
    approver = approver_session(iso_client)
    assert reset(iso_client, approver, "BOSS.ONE").status_code == 409


def test_an_unknown_account_is_404(iso_client, accounts_mode):
    approver = approver_session(iso_client)
    assert reset(iso_client, approver, "no.such.user").status_code == 404
    assert reset(iso_client, approver, "x").status_code == 404, "a name that cannot exist is the same answer"
    assert audit_rows(iso_client, action="PASSWORD_RESET") == []


@pytest.mark.parametrize("password, fragment", [("short", "at least"), ("x" * 1025, "at most"), (" " * 20, "only spaces")])
def test_a_refused_password_is_422_and_changes_nothing(iso_client, accounts_mode, password, fragment):
    approver = approver_session(iso_client)
    make_user(iso_client, "ana.analyst", "analyst")
    res = reset(iso_client, approver, "ana.analyst", password)
    assert res.status_code == 422 and fragment in res.json()["detail"]
    assert password.strip() == "" or password not in res.text
    assert another_client().post(f"{API}/auth/login", json={"username": "ana.analyst", "password": PASSWORD}).status_code == 200
    assert audit_rows(iso_client, action="PASSWORD_RESET") == []


def test_a_missing_field_is_422_and_does_not_echo_what_was_sent(iso_client, accounts_mode):
    approver = approver_session(iso_client)
    res = iso_client.post(f"{API}/auth/users/ana.analyst/password", json={"password": NEW_PASSWORD}, headers=approver)
    assert res.status_code == 422
    assert NEW_PASSWORD not in res.text


def test_a_static_token_approver_may_reset_any_account(iso_client, monkeypatch):
    monkeypatch.setattr(settings, "AUTH_MODE", "accounts")
    monkeypatch.setattr(settings, "AUTH_TOKENS", [{"name": "Automation", "role": "approver", "token": AUTOMATION_TOKEN}])
    make_user(iso_client, "ana.analyst", "analyst")
    res = iso_client.post(f"{API}/auth/users/ana.analyst/password", json={"new_password": NEW_PASSWORD},
                          headers={"Authorization": f"Bearer {AUTOMATION_TOKEN}"})
    assert res.status_code == 200
    rows = iso_client.get(f"{API}/audit-logs", params={"action": "PASSWORD_RESET"}, headers={"Authorization": f"Bearer {AUTOMATION_TOKEN}"}).json()
    assert rows[0]["actor"] == "Automation" and rows[0]["target_id"] == "ana.analyst"


# ----------------------------------------------------------------------------------- service and command line
def test_the_service_refuses_the_acting_account_and_an_unknown_one(iso_client, accounts_mode):
    make_user(iso_client, "boss.one", "approver")
    db = iso_client.session_factory()
    try:
        with pytest.raises(accounts.AccountRuleError):
            accounts.reset_password(db, "boss.one", "boss.one", NEW_PASSWORD)
        with pytest.raises(accounts.AccountNotFound):
            accounts.reset_password(db, "boss.one", "nobody.here", NEW_PASSWORD)
        with pytest.raises(ValueError):
            accounts.reset_password(db, None, "boss.one", "short")
    finally:
        db.close()


def answers(*values):
    queue = list(values)
    return lambda prompt: queue.pop(0)


def run_cli(args, *values):
    out, err = [], []
    code = cli.main(args, read_password=answers(*values), out=out.append, err=err.append)
    return code, out, err


def test_the_command_line_resets_a_password_after_asking_twice():
    run_cli(["create-user", "--username", "cli.reset", "--role", "viewer"], PASSWORD, PASSWORD)
    code, out, err = run_cli(["reset-password", "--username", "cli.reset"], NEW_PASSWORD, NEW_PASSWORD)
    assert code == 0 and err == []
    assert out == ["The password of 'cli.reset' was changed. 0 open sessions ended."]
    from app.db.session import SessionLocal
    from app.services import passwords as pw
    db = SessionLocal()
    try:
        row = db.query(UserAccount).filter(UserAccount.username == "cli.reset").one()
        assert pw.verify_password(NEW_PASSWORD, row.password_hash) and not pw.verify_password(PASSWORD, row.password_hash)
    finally:
        db.close()
    assert NEW_PASSWORD not in " ".join(out + err)


def test_the_command_line_refuses_mismatched_weak_and_unknown_without_changing_anything():
    run_cli(["create-user", "--username", "cli.keep", "--role", "viewer"], PASSWORD, PASSWORD)
    code, _, err = run_cli(["reset-password", "--username", "cli.keep"], NEW_PASSWORD, NEW_PASSWORD + "x")
    assert code == 2 and "do not match" in err[0]
    code, _, err = run_cli(["reset-password", "--username", "cli.keep"], "short", "short")
    assert code == 2 and "at least" in err[0]
    code, _, err = run_cli(["reset-password", "--username", "cli.nobody"], NEW_PASSWORD, NEW_PASSWORD)
    assert code == 2 and "No account" in err[0]
    from app.db.session import SessionLocal
    from app.services import passwords as pw
    db = SessionLocal()
    try:
        row = db.query(UserAccount).filter(UserAccount.username == "cli.keep").one()
        assert pw.verify_password(PASSWORD, row.password_hash)
    finally:
        db.close()
    assert PASSWORD not in " ".join(err) and NEW_PASSWORD not in " ".join(err)


def test_the_command_line_never_takes_the_password_as_an_argument():
    parser = cli.build_parser()
    with pytest.raises(SystemExit):
        parser.parse_args(["reset-password", "--username", "x", "--password", NEW_PASSWORD])
