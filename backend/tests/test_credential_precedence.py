"""Credential precedence in accounts mode: a valid account cookie wins over a bearer token sent in the same request.

Covered: the identity and the role come from the account, writes with a cookie still need the CSRF token, a static bearer token
works when no valid cookie exists, logout revokes the cookie session on the server even when a bearer token is also sent, and
token mode is unchanged. Each test uses its own temporary database (conftest's iso_client)."""
import pytest

from app.core.config import settings
from app.services import accounts

API = "/api/v1"
PASSWORD = "a long enough passphrase"
STATIC_ANALYST = "static-analyst-token-0123456789"
STATIC_VIEWER = "static-viewer-token-0123456789"


@pytest.fixture
def accounts_mode(monkeypatch):
    monkeypatch.setattr(settings, "AUTH_MODE", "accounts")
    monkeypatch.setattr(settings, "AUTH_TOKENS", [
        {"name": "Automation Analyst", "role": "analyst", "token": STATIC_ANALYST},
        {"name": "Automation Viewer", "role": "viewer", "token": STATIC_VIEWER},
    ])
    yield


def make_user(client, username, role):
    db = client.session_factory()
    try:
        accounts.create_user(db, username, role, PASSWORD)
    finally:
        db.close()


def sign_in(client, username):
    res = client.post(f"{API}/auth/login", json={"username": username, "password": PASSWORD})
    assert res.status_code == 200, res.text
    return res


def bearer(token):
    return {"Authorization": f"Bearer {token}"}


def both(login, token):
    """The headers of a request that carries the account cookie (already in the client) and a bearer token, plus the CSRF token."""
    return {**bearer(token), "X-CSRF-Token": login.json()["csrf_token"]}


# ----------------------------------------------------------------------------------- identity
def test_with_a_cookie_and_a_bearer_token_the_account_is_the_identity(iso_client, accounts_mode):
    make_user(iso_client, "vera.viewer", "viewer")
    sign_in(iso_client, "vera.viewer")
    me = iso_client.get(f"{API}/auth/me", headers=bearer(STATIC_ANALYST)).json()
    assert me["mode"] == "accounts", "the cookie session, not the bearer token, decides the identity"
    assert me["name"] == "vera.viewer" and me["role"] == "viewer"


def test_the_bearer_token_does_not_raise_the_role_of_a_viewer_account(iso_client, accounts_mode):
    make_user(iso_client, "vera.viewer", "viewer")
    login = sign_in(iso_client, "vera.viewer")
    # the static token is an analyst; the account is a viewer, so the write is refused
    res = iso_client.post(f"{API}/alerts/seed", headers=both(login, STATIC_ANALYST))
    assert res.status_code == 403


def test_the_account_role_is_enforced_when_the_account_has_more_than_the_bearer(iso_client, accounts_mode):
    make_user(iso_client, "ana.analyst", "analyst")
    login = sign_in(iso_client, "ana.analyst")
    # the static token is only a viewer; the analyst account may still do analyst work
    res = iso_client.post(f"{API}/alerts/seed", headers=both(login, STATIC_VIEWER))
    assert res.status_code == 200


def test_a_cookie_write_still_needs_the_csrf_token_even_when_a_bearer_token_is_valid(iso_client, accounts_mode):
    make_user(iso_client, "ana.analyst", "analyst")
    sign_in(iso_client, "ana.analyst")
    res = iso_client.post(f"{API}/alerts/seed", headers=bearer(STATIC_ANALYST))
    assert res.status_code == 403, "no fallback to the bearer token for a refused cookie write"


def test_a_cookie_write_with_the_csrf_token_succeeds_alongside_a_bearer_token(iso_client, accounts_mode):
    make_user(iso_client, "ana.analyst", "analyst")
    login = sign_in(iso_client, "ana.analyst")
    assert iso_client.post(f"{API}/alerts/seed", headers=both(login, STATIC_VIEWER)).status_code == 200


def test_a_wrong_bearer_token_does_not_override_a_valid_cookie(iso_client, accounts_mode):
    make_user(iso_client, "vera.viewer", "viewer")
    sign_in(iso_client, "vera.viewer")
    res = iso_client.get(f"{API}/auth/me", headers=bearer("not-a-real-token-0123456789"))
    assert res.status_code == 200 and res.json()["name"] == "vera.viewer"


# ----------------------------------------------------------------------------------- fallback to bearer
def test_a_bearer_token_alone_still_works_in_accounts_mode(iso_client, accounts_mode):
    me = iso_client.get(f"{API}/auth/me", headers=bearer(STATIC_ANALYST)).json()
    assert me["mode"] == "token" and me["name"] == "Automation Analyst" and me["role"] == "analyst"
    assert iso_client.get(f"{API}/alerts", headers=bearer(STATIC_VIEWER)).status_code == 200


def test_a_bearer_token_keeps_its_own_role_when_no_cookie_is_present(iso_client, accounts_mode):
    assert iso_client.post(f"{API}/alerts/seed", headers=bearer(STATIC_VIEWER)).status_code == 403
    assert iso_client.post(f"{API}/alerts/seed", headers=bearer(STATIC_ANALYST)).status_code == 200


def test_after_logout_the_bearer_token_is_the_identity_again(iso_client, accounts_mode):
    make_user(iso_client, "vera.viewer", "viewer")
    login = sign_in(iso_client, "vera.viewer")
    iso_client.post(f"{API}/auth/logout", headers={"X-CSRF-Token": login.json()["csrf_token"]})
    me = iso_client.get(f"{API}/auth/me", headers=bearer(STATIC_ANALYST)).json()
    assert me["mode"] == "token" and me["name"] == "Automation Analyst"


def test_a_revoked_cookie_with_a_bearer_token_falls_back_to_the_token_not_the_account(iso_client, accounts_mode):
    make_user(iso_client, "vera.viewer", "viewer")
    sign_in(iso_client, "vera.viewer")
    stale = iso_client.cookies.get("socmind_session")
    db = iso_client.session_factory()
    try:
        from app.models.auth_models import AuthSession
        from app.core.clock import utc_now
        import hashlib
        row = db.get(AuthSession, hashlib.sha256(stale.encode()).hexdigest())
        accounts.end_session(db, row, reason="logout", now=utc_now())
    finally:
        db.close()
    me = iso_client.get(f"{API}/auth/me", headers=bearer(STATIC_ANALYST)).json()
    assert me["mode"] == "token" and me["name"] == "Automation Analyst"


# ----------------------------------------------------------------------------------- logout and revocation
def test_logout_with_a_bearer_token_also_present_revokes_the_cookie_session(iso_client, accounts_mode):
    make_user(iso_client, "ana.analyst", "analyst")
    login = sign_in(iso_client, "ana.analyst")
    old_cookie = iso_client.cookies.get("socmind_session")
    res = iso_client.post(f"{API}/auth/logout", headers=both(login, STATIC_ANALYST))
    assert res.status_code == 200 and res.json() == {"authenticated": False}
    iso_client.cookies.set("socmind_session", old_cookie)                            # a replayed copy of the cookie
    me = iso_client.get(f"{API}/auth/me", headers=bearer(STATIC_VIEWER)).json()
    assert me["mode"] == "token", "the replayed cookie must not authenticate, even with a bearer token present"
    assert iso_client.get(f"{API}/auth/me").status_code == 401                        # and not without one either


def test_logout_with_only_a_bearer_token_does_not_revoke_an_open_cookie_session(iso_client, accounts_mode):
    make_user(iso_client, "ana.analyst", "analyst")
    sign_in(iso_client, "ana.analyst")
    iso_client.post(f"{API}/auth/logout", headers=bearer(STATIC_ANALYST))
    assert iso_client.get(f"{API}/auth/me").status_code == 200, "a logout that did not carry the session ends nothing"


def test_a_session_still_open_on_another_client_is_not_revoked_by_one_logout(iso_client, accounts_mode):
    make_user(iso_client, "ana.analyst", "analyst")
    first = sign_in(iso_client, "ana.analyst")
    other = iso_client.__class__(iso_client.app)
    sign_in(other, "ana.analyst")
    iso_client.post(f"{API}/auth/logout", headers={"X-CSRF-Token": first.json()["csrf_token"]})
    assert other.get(f"{API}/auth/me").status_code == 200


# ----------------------------------------------------------------------------------- invalid bearer, no cookie
def test_an_invalid_bearer_token_with_no_cookie_is_refused(iso_client, accounts_mode):
    res = iso_client.get(f"{API}/alerts", headers=bearer("not-a-real-token-0123456789"))
    assert res.status_code == 401


# ----------------------------------------------------------------------------------- token mode unchanged
def test_token_mode_ignores_account_cookies_completely(iso_client, monkeypatch):
    monkeypatch.setattr(settings, "AUTH_MODE", "token")
    monkeypatch.setattr(settings, "AUTH_TOKENS", [{"name": "Automation Analyst", "role": "analyst", "token": STATIC_ANALYST}])
    make_user(iso_client, "ana.analyst", "analyst")
    monkeypatch.setattr(settings, "AUTH_MODE", "accounts")
    sign_in(iso_client, "ana.analyst")
    monkeypatch.setattr(settings, "AUTH_MODE", "token")
    assert iso_client.get(f"{API}/alerts").status_code == 401, "a cookie alone is not a credential in token mode"
    assert iso_client.get(f"{API}/alerts", headers=bearer(STATIC_ANALYST)).status_code == 200
