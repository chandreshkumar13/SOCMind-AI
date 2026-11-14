"""Sign-in and sign-out over HTTP in AUTH_MODE=accounts: cookies, CSRF, roles, logout, lockout, expiry, disabled users, the audit
trail and the coexistence with static bearer tokens. Each test uses its own temporary database (conftest's iso_client)."""
from datetime import datetime, timedelta

import pytest

from app.core.config import settings
from app.models.auth_models import UserAccount
from app.models.models import AuditLogModel
from app.services import accounts

PASSWORD = "a long enough passphrase"
API = "/api/v1"
TOKEN_FOR_AUTOMATION = "static-token-for-automation-0123456789"


@pytest.fixture
def accounts_mode(monkeypatch):
    monkeypatch.setattr(settings, "AUTH_MODE", "accounts")
    monkeypatch.setattr(settings, "AUTH_TOKENS", [])
    yield


@pytest.fixture
def clock(monkeypatch):
    """A clock the account service reads. Tests move it forward instead of sleeping."""
    now = {"t": datetime(2026, 11, 10, 9, 0, 0)}
    monkeypatch.setattr(accounts, "utc_now", lambda: now["t"])

    class Clock:
        def set(self, value):
            now["t"] = value

        def advance(self, **delta):
            now["t"] = now["t"] + timedelta(**delta)

        def now(self):
            return now["t"]
    return Clock()


def make_user(client, username, role, password=PASSWORD):
    db = client.session_factory()
    try:
        return accounts.create_user(db, username, role, password)
    finally:
        db.close()


def sign_in(client, username, password=PASSWORD):
    return client.post(f"{API}/auth/login", json={"username": username, "password": password})


def csrf_headers(login_response):
    return {"X-CSRF-Token": login_response.json()["csrf_token"]}


# ----------------------------------------------------------------------------------- public and basic behaviour
def test_status_is_public_and_tells_the_page_to_show_sign_in(iso_client, accounts_mode):
    body = iso_client.get(f"{API}/auth/status").json()
    assert body == {"mode": "accounts", "login_required": True, "sign_in": True}


def test_a_protected_route_without_a_session_says_to_sign_in(iso_client, accounts_mode):
    res = iso_client.get(f"{API}/alerts")
    assert res.status_code == 401 and res.json()["detail"] == "Sign in to continue."


def test_a_form_post_cannot_sign_in(iso_client, accounts_mode):
    """A cross-site HTML form can only send form-encoded data. The sign-in model accepts JSON only, so the request is refused
    (by body validation, 422, or by the content-type check, 415) and no session cookie is set."""
    make_user(iso_client, "ana.analyst", "analyst")
    res = iso_client.post(f"{API}/auth/login", data={"username": "ana.analyst", "password": PASSWORD})
    assert res.status_code in (415, 422)
    assert "socmind_session" not in res.headers.get("set-cookie", "")
    assert iso_client.get(f"{API}/auth/me").status_code == 401


def test_a_wrong_password_and_an_unknown_name_get_the_same_answer(iso_client, accounts_mode):
    make_user(iso_client, "ana.analyst", "analyst")
    wrong = sign_in(iso_client, "ana.analyst", "wrong-wrong-wrong")
    unknown = sign_in(iso_client, "no-such-person", "wrong-wrong-wrong")
    assert wrong.status_code == unknown.status_code == 401
    assert wrong.json() == unknown.json() == {"detail": "Invalid username or password."}


def test_a_right_password_sets_an_httponly_strict_cookie_and_returns_no_session_token(iso_client, accounts_mode):
    make_user(iso_client, "ana.analyst", "analyst")
    res = sign_in(iso_client, "ana.analyst")
    assert res.status_code == 200
    cookie_header = res.headers["set-cookie"]
    assert "socmind_session=" in cookie_header and "HttpOnly" in cookie_header
    assert "samesite=strict" in cookie_header.lower() and "Path=/" in cookie_header
    body = res.json()
    assert body["name"] == "ana.analyst" and body["role"] == "analyst" and body["authenticated"] is True
    session_value = iso_client.cookies.get("socmind_session")
    assert session_value and session_value not in res.text, "the session token must never appear in the response body"
    assert PASSWORD not in res.text


def test_the_cookie_is_secure_in_production(iso_client, accounts_mode, monkeypatch):
    monkeypatch.setattr(settings, "ENVIRONMENT", "production")
    make_user(iso_client, "ana.analyst", "analyst")
    assert "Secure" in sign_in(iso_client, "ana.analyst").headers["set-cookie"]


def test_the_cookie_is_not_secure_by_default_in_development(iso_client, accounts_mode):
    make_user(iso_client, "ana.analyst", "analyst")
    assert "Secure" not in sign_in(iso_client, "ana.analyst").headers["set-cookie"]


def test_me_reports_the_account_and_the_csrf_token_for_the_session(iso_client, accounts_mode):
    make_user(iso_client, "ana.analyst", "analyst")
    login = sign_in(iso_client, "ana.analyst")
    me = iso_client.get(f"{API}/auth/me").json()
    assert me["mode"] == "accounts" and me["name"] == "ana.analyst" and me["role"] == "analyst"
    assert me["csrf_token"] == login.json()["csrf_token"]
    assert me["idle_timeout_minutes"] == 30


# ----------------------------------------------------------------------------------- CSRF
def test_a_state_changing_request_needs_the_session_csrf_token(iso_client, accounts_mode):
    make_user(iso_client, "ana.analyst", "analyst")
    login = sign_in(iso_client, "ana.analyst")
    assert iso_client.post(f"{API}/alerts/seed").status_code == 403                              # no header
    assert iso_client.post(f"{API}/alerts/seed", headers={"X-CSRF-Token": "wrong"}).status_code == 403
    assert iso_client.post(f"{API}/alerts/seed", headers=csrf_headers(login)).status_code == 200


def test_reads_do_not_need_the_csrf_token(iso_client, accounts_mode):
    make_user(iso_client, "ana.analyst", "analyst")
    sign_in(iso_client, "ana.analyst")
    assert iso_client.get(f"{API}/alerts").status_code == 200


def test_a_csrf_token_from_another_session_does_not_work(iso_client, accounts_mode):
    make_user(iso_client, "ana.analyst", "analyst")
    first = sign_in(iso_client, "ana.analyst")                # this client's cookie is the first session
    other = iso_client.__class__(iso_client.app)
    second = sign_in(other, "ana.analyst")                    # a second session, in its own cookie jar
    assert other.post(f"{API}/alerts/seed", headers=csrf_headers(first)).status_code == 403     # the first session's token
    assert other.post(f"{API}/alerts/seed", headers=csrf_headers(second)).status_code == 200    # its own token works


# ----------------------------------------------------------------------------------- roles
def test_the_viewer_analyst_and_approver_roles_are_kept_for_sessions(iso_client, accounts_mode):
    make_user(iso_client, "vera.viewer", "viewer")
    make_user(iso_client, "ana.analyst", "analyst")
    make_user(iso_client, "ola.approver", "approver")

    viewer = iso_client
    v = sign_in(viewer, "vera.viewer")
    assert viewer.get(f"{API}/alerts").status_code == 200
    assert viewer.post(f"{API}/alerts/seed", headers=csrf_headers(v)).status_code == 403     # analyst needed

    analyst_client = iso_client.__class__(iso_client.app)
    a = sign_in(analyst_client, "ana.analyst")
    assert analyst_client.post(f"{API}/alerts/seed", headers=csrf_headers(a)).status_code == 200
    assert analyst_client.post(f"{API}/incidents/NO-SUCH/approve", json={"reviewer": "x"}, headers=csrf_headers(a)).status_code == 403

    approver_client = iso_client.__class__(iso_client.app)
    o = sign_in(approver_client, "ola.approver")
    res = approver_client.post(f"{API}/incidents/NO-SUCH/approve", json={"reviewer": "x"}, headers=csrf_headers(o))
    assert res.status_code == 404, "an approver passes the role check and reaches the handler"


def test_the_signed_in_name_is_the_account_name(iso_client, accounts_mode):
    make_user(iso_client, "ola.approver", "approver")
    sign_in(iso_client, "ola.approver")
    me = iso_client.get(f"{API}/auth/me").json()
    assert me["name"] == "ola.approver"


# ----------------------------------------------------------------------------------- logout
def test_logout_needs_the_csrf_token_and_then_ends_the_session(iso_client, accounts_mode):
    make_user(iso_client, "ana.analyst", "analyst")
    login = sign_in(iso_client, "ana.analyst")
    old_cookie = iso_client.cookies.get("socmind_session")
    assert iso_client.post(f"{API}/auth/logout").status_code == 403
    assert iso_client.get(f"{API}/auth/me").status_code == 200, "a refused logout must not end the session"

    res = iso_client.post(f"{API}/auth/logout", headers=csrf_headers(login))
    assert res.status_code == 200 and res.json() == {"authenticated": False}
    assert "socmind_session=" in res.headers["set-cookie"] and "Max-Age=0" in res.headers["set-cookie"]
    assert iso_client.get(f"{API}/auth/me").status_code == 401


def test_a_logged_out_cookie_is_refused_by_the_server_even_if_it_is_replayed(iso_client, accounts_mode):
    make_user(iso_client, "ana.analyst", "analyst")
    login = sign_in(iso_client, "ana.analyst")
    old_cookie = iso_client.cookies.get("socmind_session")
    iso_client.post(f"{API}/auth/logout", headers=csrf_headers(login))
    iso_client.cookies.set("socmind_session", old_cookie)                       # as if the browser kept a copy
    assert iso_client.get(f"{API}/auth/me").status_code == 401                  # the server revoked the session


def test_logout_changes_nothing_for_a_static_bearer_token(iso_client, accounts_mode, monkeypatch):
    monkeypatch.setattr(settings, "AUTH_TOKENS", [{"name": "Automation", "role": "analyst", "token": TOKEN_FOR_AUTOMATION}])
    res = iso_client.post(f"{API}/auth/logout", headers={"Authorization": f"Bearer {TOKEN_FOR_AUTOMATION}"})
    assert res.status_code == 200
    assert iso_client.get(f"{API}/alerts", headers={"Authorization": f"Bearer {TOKEN_FOR_AUTOMATION}"}).status_code == 200


# ----------------------------------------------------------------------------------- lockout
def test_five_wrong_passwords_lock_the_pair_then_the_right_password_is_refused(iso_client, accounts_mode):
    make_user(iso_client, "ana.analyst", "analyst")
    for _ in range(settings.LOGIN_MAX_FAILURES):
        assert sign_in(iso_client, "ana.analyst", "wrong-wrong-wrong").status_code == 401
    locked = sign_in(iso_client, "ana.analyst")
    assert locked.status_code == 429
    assert "Too many failed sign-in attempts" in locked.json()["detail"]
    assert "15 minutes" in locked.json()["detail"]


def test_a_lock_for_an_unknown_name_looks_exactly_like_a_lock_for_a_real_one(iso_client, accounts_mode):
    make_user(iso_client, "ana.analyst", "analyst")
    for name in ("ana.analyst", "no-such-person"):
        for _ in range(settings.LOGIN_MAX_FAILURES):
            sign_in(iso_client, name, "wrong-wrong-wrong")
    real = sign_in(iso_client, "ana.analyst", "wrong-wrong-wrong")
    fake = sign_in(iso_client, "no-such-person", "wrong-wrong-wrong")
    assert real.status_code == fake.status_code == 429 and real.json() == fake.json()


# ----------------------------------------------------------------------------------- disabled users and expiry
def test_a_disabled_user_loses_the_open_session_on_the_next_request(iso_client, accounts_mode):
    make_user(iso_client, "ana.analyst", "analyst")
    sign_in(iso_client, "ana.analyst")
    assert iso_client.get(f"{API}/auth/me").status_code == 200
    db = iso_client.session_factory()
    try:
        accounts.set_active(db, "ana.analyst", False)
    finally:
        db.close()
    assert iso_client.get(f"{API}/auth/me").status_code == 401
    assert sign_in(iso_client, "ana.analyst").status_code == 401


def test_a_session_left_idle_for_thirty_minutes_ends(iso_client, accounts_mode, clock):
    make_user(iso_client, "ana.analyst", "analyst")
    sign_in(iso_client, "ana.analyst")
    clock.advance(minutes=31)
    assert iso_client.get(f"{API}/auth/me").status_code == 401


def test_a_session_in_use_lasts_until_the_eight_hour_limit(iso_client, accounts_mode, clock):
    make_user(iso_client, "ana.analyst", "analyst")
    sign_in(iso_client, "ana.analyst")
    for _ in range(23):                                   # 23 uses, 20 minutes apart: 7 h 40 min
        clock.advance(minutes=20)
        assert iso_client.get(f"{API}/auth/me").status_code == 200
    clock.advance(minutes=20)                             # now 8 h: the absolute limit ends it although it is in use
    assert iso_client.get(f"{API}/auth/me").status_code == 401


# ----------------------------------------------------------------------------------- audit and secrets
def _audit(iso_client):
    db = iso_client.session_factory()
    try:
        return [(row.actor, row.action, row.details) for row in db.query(AuditLogModel).order_by(AuditLogModel.id).all()]
    finally:
        db.close()


def test_sign_ins_failures_lockouts_and_sign_outs_are_audited_without_secrets(iso_client, accounts_mode):
    make_user(iso_client, "ana.analyst", "analyst")
    sign_in(iso_client, "ana.analyst", "wrong-wrong-wrong")                       # LOGIN_FAILED
    login = sign_in(iso_client, "ana.analyst")                                    # LOGIN
    iso_client.post(f"{API}/auth/logout", headers=csrf_headers(login))           # LOGOUT
    sign_in(iso_client, "<script>alert(1)</script>", "wrong-wrong-wrong")         # LOGIN_FAILED, invalid name
    rows = _audit(iso_client)
    actions = [action for _, action, _ in rows]
    assert "LOGIN_FAILED" in actions and "LOGIN" in actions and "LOGOUT" in actions
    assert ("ana.analyst", "LOGIN") in [(a, b) for a, b, _ in rows]
    assert ("(invalid username)", "LOGIN_FAILED") in [(a, b) for a, b, _ in rows]
    everything = repr(rows)
    assert PASSWORD not in everything and "wrong-wrong-wrong" not in everything


def test_a_lockout_is_audited(iso_client, accounts_mode):
    make_user(iso_client, "ana.analyst", "analyst")
    for _ in range(settings.LOGIN_MAX_FAILURES):
        sign_in(iso_client, "ana.analyst", "wrong-wrong-wrong")
    sign_in(iso_client, "ana.analyst")
    assert "LOGIN_LOCKED" in [action for _, action, _ in _audit(iso_client)]


def test_passwords_never_reach_the_log(iso_client, accounts_mode, caplog):
    make_user(iso_client, "ana.analyst", "analyst")
    with caplog.at_level("DEBUG"):
        sign_in(iso_client, "ana.analyst", "wrong-wrong-wrong")
        sign_in(iso_client, "ana.analyst")
    assert "wrong-wrong-wrong" not in caplog.text and PASSWORD not in caplog.text


# ----------------------------------------------------------------------------------- coexistence
def test_static_bearer_tokens_still_work_in_accounts_mode(iso_client, accounts_mode, monkeypatch):
    monkeypatch.setattr(settings, "AUTH_TOKENS", [{"name": "Automation", "role": "analyst", "token": TOKEN_FOR_AUTOMATION}])
    me = iso_client.get(f"{API}/auth/me", headers={"Authorization": f"Bearer {TOKEN_FOR_AUTOMATION}"}).json()
    assert me["mode"] == "token" and me["name"] == "Automation" and me["role"] == "analyst"


def test_a_wrong_bearer_token_is_refused_in_accounts_mode(iso_client, accounts_mode):
    res = iso_client.get(f"{API}/alerts", headers={"Authorization": "Bearer not-a-real-token-0123456789"})
    assert res.status_code == 401


def test_sign_in_is_not_offered_in_token_mode(iso_client, monkeypatch):
    monkeypatch.setattr(settings, "AUTH_MODE", "token")
    monkeypatch.setattr(settings, "AUTH_TOKENS", [{"name": "Automation", "role": "analyst", "token": TOKEN_FOR_AUTOMATION}])
    assert iso_client.post(f"{API}/auth/login", json={"username": "x", "password": "y"}).status_code == 404
    assert iso_client.get(f"{API}/auth/status").json()["sign_in"] is False


def test_demo_mode_is_unchanged_and_needs_no_session(iso_client, monkeypatch):
    monkeypatch.setattr(settings, "AUTH_MODE", "disabled")
    assert iso_client.get(f"{API}/alerts").status_code == 200
    assert iso_client.get(f"{API}/auth/status").json()["login_required"] is False
    assert iso_client.get(f"{API}/auth/me").json()["mode"] == "disabled"
