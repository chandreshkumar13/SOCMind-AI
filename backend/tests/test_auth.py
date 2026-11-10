"""Authentication and roles (C8).

AUTH_MODE=disabled (default): the demo mode. No token is needed, every action is allowed and reviewer names are self-asserted.
AUTH_MODE=token: every request needs 'Authorization: Bearer <token>' from AUTH_TOKENS. Roles are ordered:
viewer (read) < analyst (work the pipeline, ingest, triage, enrich, recommend, simulate) < approver (approve or reject).
Missing or unknown tokens get 401; a known token without the role gets 403. The reviewer name comes from the token.
"""
import pytest

from app.core.auth import validate_auth_config
from app.core.config import settings

VIEWER = "viewer-token-0123456789abcdef"
ANALYST = "analyst-token-0123456789abcdef"
APPROVER = "approver-token-0123456789abcdef"


@pytest.fixture
def token_mode(monkeypatch):
    monkeypatch.setattr(settings, "AUTH_MODE", "token")
    monkeypatch.setattr(settings, "AUTH_TOKENS", [
        {"name": "Vera Viewer", "role": "viewer", "token": VIEWER},
        {"name": "Ana Analyst", "role": "analyst", "token": ANALYST},
        {"name": "Ola Approver", "role": "approver", "token": APPROVER},
    ])
    yield


def _as(token):
    return {"Authorization": f"Bearer {token}"}


def _ingest(client, alert_id, headers, title="Ransomware file encryption on FS-1"):
    body = {"id": alert_id, "alert_title": title, "source": "CrowdStrike EDR", "severity": "CRITICAL", "host": "FS-1",
            "timestamp": "2026-09-03T08:00:00Z", "username": "svc-backup"}
    return client.post("/api/v1/alerts", json=body, headers=headers)


def test_disabled_mode_needs_no_token_and_says_so(iso_client):
    assert iso_client.get("/api/v1/alerts").status_code == 200
    me = iso_client.get("/api/v1/auth/me").json()
    assert me["mode"] == "disabled" and me["authenticated"] is False


def test_token_mode_without_a_token_is_401(iso_client, token_mode):
    assert iso_client.get("/api/v1/alerts").status_code == 401
    assert iso_client.get("/api/v1/auth/me").status_code == 401


def test_an_unknown_token_is_401_and_is_not_echoed_back(iso_client, token_mode):
    response = iso_client.get("/api/v1/alerts", headers=_as("not-a-real-token-0000000000"))
    assert response.status_code == 401
    assert "not-a-real-token" not in response.text


def test_a_viewer_can_read_but_not_change(iso_client, token_mode):
    assert iso_client.get("/api/v1/alerts", headers=_as(VIEWER)).status_code == 200
    assert _ingest(iso_client, "AU-V", _as(VIEWER)).status_code == 403


def test_an_analyst_can_work_the_alerts_but_cannot_approve(iso_client, token_mode):
    assert _ingest(iso_client, "AU-A", _as(ANALYST)).status_code == 201
    assert iso_client.post("/api/v1/alerts/AU-A/triage", headers=_as(ANALYST)).status_code == 200
    body = {"reviewer": "anyone", "reason": "ok"}
    # 403 is decided before the incident is looked up, so a missing incident shows the role check on its own
    assert iso_client.post("/api/v1/incidents/INC-NONE/approve", json=body, headers=_as(ANALYST)).status_code == 403


def test_an_approver_passes_the_role_check_and_gets_a_404_for_a_missing_incident(iso_client, token_mode):
    body = {"reviewer": "anyone", "reason": "ok"}
    assert iso_client.post("/api/v1/incidents/INC-NONE/approve", json=body, headers=_as(APPROVER)).status_code == 404


def test_the_reviewer_name_comes_from_the_token_not_the_request(iso_client, token_mode):
    assert _ingest(iso_client, "AU-R1", _as(ANALYST)).status_code == 201
    assert _ingest(iso_client, "AU-R2", _as(ANALYST), title="Ransomware bulk file rename on FS-1").status_code == 201
    assert iso_client.post("/api/v1/incidents/correlate", headers=_as(ANALYST)).status_code == 200
    incident = iso_client.get("/api/v1/incidents", headers=_as(VIEWER)).json()[0]["id"]
    assert iso_client.post(f"/api/v1/incidents/{incident}/investigate", headers=_as(ANALYST)).status_code == 200
    assert iso_client.post(f"/api/v1/incidents/{incident}/recommend", headers=_as(ANALYST)).status_code == 200
    decided = iso_client.post(f"/api/v1/incidents/{incident}/approve",
                              json={"reviewer": "Somebody Else", "reason": "reviewed"}, headers=_as(APPROVER))
    assert decided.status_code == 200, decided.text
    assert "Somebody Else" not in decided.text
    assert "Ola Approver" in decided.text


def test_auth_me_reports_the_role_and_name_from_the_token(iso_client, token_mode):
    me = iso_client.get("/api/v1/auth/me", headers=_as(ANALYST)).json()
    assert me == {"mode": "token", "authenticated": True, "name": "Ana Analyst", "role": "analyst"}


def test_the_configuration_endpoint_never_returns_a_token(iso_client, token_mode):
    text = iso_client.get("/api/v1/config", headers=_as(VIEWER)).text
    assert VIEWER not in text and ANALYST not in text and APPROVER not in text


def test_misconfigured_token_mode_is_refused_at_startup():
    with pytest.raises(ValueError, match="no tokens"):
        validate_auth_config("token", [])
    with pytest.raises(ValueError, match="at least 16"):
        validate_auth_config("token", [{"name": "x", "role": "viewer", "token": "short"}])
    with pytest.raises(ValueError, match="role"):
        validate_auth_config("token", [{"name": "x", "role": "admin", "token": "a" * 20}])
    with pytest.raises(ValueError, match="AUTH_MODE"):
        validate_auth_config("sometimes", [])
    validate_auth_config("disabled", [])                                   # always fine
    validate_auth_config("token", [{"name": "x", "role": "viewer", "token": "a" * 20}])
