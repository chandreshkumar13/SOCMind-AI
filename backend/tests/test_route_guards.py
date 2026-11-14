"""Every API route has an explicit access decision (final review, item 6).

A route that is not listed in EXPECTED fails the first test, so a new endpoint cannot ship without a decision about who may
call it. The other tests check the decision against the real application in token mode: no token gets 401, a token below the
required role gets 403, and a public route answers without a token."""
import pytest

from app.core.config import settings
from app.main import app

# (method, path) -> the lowest role that may call it. None = public. Every protected route also needs a valid token.
EXPECTED = {
    ("GET", "/api/v1/health"): None,
    ("GET", "/api/v1/version"): None,
    ("GET", "/api/v1/auth/me"): "viewer",
    ("GET", "/api/v1/auth/status"): None,
    ("POST", "/api/v1/auth/login"): None,
    ("POST", "/api/v1/auth/logout"): "viewer",
    ("POST", "/api/v1/alerts"): "analyst",
    ("GET", "/api/v1/alerts"): "viewer",
    ("GET", "/api/v1/alerts/{alert_id}"): "viewer",
    ("POST", "/api/v1/alerts/{alert_id}/triage"): "analyst",
    ("POST", "/api/v1/alerts/{alert_id}/enrich"): "analyst",
    ("DELETE", "/api/v1/alerts/{alert_id}"): "analyst",
    ("POST", "/api/v1/alerts/seed"): "analyst",
    ("GET", "/api/v1/audit-logs"): "viewer",
    ("GET", "/api/v1/incidents"): "viewer",
    ("GET", "/api/v1/incidents/{incident_id}"): "viewer",
    ("POST", "/api/v1/incidents/correlate"): "analyst",
    ("POST", "/api/v1/incidents/{incident_id}/investigate"): "analyst",
    ("POST", "/api/v1/incidents/{incident_id}/recommend"): "analyst",
    ("POST", "/api/v1/incidents/{incident_id}/approve"): "approver",
    ("POST", "/api/v1/incidents/{incident_id}/reject"): "approver",
    ("POST", "/api/v1/incidents/{incident_id}/simulate"): "analyst",
    ("POST", "/api/v1/pipeline/run"): "analyst",
    ("GET", "/api/v1/pipeline/runs"): "viewer",
    ("GET", "/api/v1/agents"): "viewer",
    ("GET", "/api/v1/stats"): "viewer",
    ("GET", "/api/v1/config"): "viewer",
}
ROLE_TOKENS = {
    "viewer": "viewer-token-0123456789abcdef",
    "analyst": "analyst-token-0123456789abcdef",
    "approver": "approver-token-0123456789abcdef",
}
RANK = {"viewer": 0, "analyst": 1, "approver": 2}


def _api_routes():
    """Every (method, path) under the API prefix. Read from the OpenAPI schema because included routers are wrapped in
    FastAPI >= 0.13x, so walking app.routes would find nothing and the check would pass for the wrong reason."""
    paths = app.openapi()["paths"]
    found = [(method.upper(), path) for path, ops in paths.items() if path.startswith(settings.API_V1_STR)
             for method in ops if method in {"get", "post", "put", "patch", "delete"}]
    assert found, "no API routes found: the route enumeration is broken"
    return found


def _concrete(path):
    return path.replace("{alert_id}", "NO-SUCH-ALERT").replace("{incident_id}", "NO-SUCH-INCIDENT")


@pytest.fixture
def token_mode(monkeypatch):
    monkeypatch.setattr(settings, "AUTH_MODE", "token")
    monkeypatch.setattr(settings, "AUTH_TOKENS", [{"name": f"{role} user", "role": role, "token": token}
                                                  for role, token in ROLE_TOKENS.items()])
    yield


def test_every_api_route_has_an_access_decision():
    found = set(_api_routes())
    assert found == set(EXPECTED), (
        f"unclassified routes: {sorted(found - set(EXPECTED))}; stale entries: {sorted(set(EXPECTED) - found)}")


def test_no_token_gets_401_on_every_protected_route_and_public_routes_answer(iso_client, token_mode):
    for (method, path), role in EXPECTED.items():
        res = iso_client.request(method, _concrete(path))
        if role is None:
            assert res.status_code != 401, (method, path)
        else:
            assert res.status_code == 401, (method, path, res.status_code)
            assert "WWW-Authenticate" in res.headers


@pytest.mark.parametrize("token_role", ["viewer", "analyst", "approver"])
def test_each_role_is_refused_exactly_the_routes_above_it(iso_client, token_mode, token_role):
    headers = {"Authorization": f"Bearer {ROLE_TOKENS[token_role]}"}
    for (method, path), role in EXPECTED.items():
        if role is None:
            continue
        res = iso_client.request(method, _concrete(path), headers=headers)
        if RANK[token_role] < RANK[role]:
            assert res.status_code == 403, (token_role, method, path, res.status_code)
        else:
            assert res.status_code not in (401, 403), (token_role, method, path, res.status_code)


def test_the_read_endpoints_never_return_a_token(iso_client, token_mode):
    headers = {"Authorization": f"Bearer {ROLE_TOKENS['viewer']}"}
    for path in ("/api/v1/config", "/api/v1/auth/me", "/api/v1/stats"):
        body = iso_client.get(path, headers=headers).text
        assert not any(token in body for token in ROLE_TOKENS.values()), path
