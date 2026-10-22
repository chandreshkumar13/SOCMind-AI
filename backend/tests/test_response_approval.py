from app.agents.response.response_agent import ResponseAgent


def _incidents(client):
    client.post("/api/v1/alerts/seed")
    for i in range(1, 11):
        client.post(f"/api/v1/alerts/ALT-2026-{i:03d}/enrich")
    client.post("/api/v1/incidents/correlate")
    incs = client.get("/api/v1/incidents").json()
    by = {("fin" if "ALT-2026-001" in i["correlated_alert_ids"] else "dc"): i["id"] for i in incs}
    return by


def test_finance_incident_recommendations(iso_client):
    inc = _incidents(iso_client)["fin"]
    body = iso_client.post(f"/api/v1/incidents/{inc}/recommend").json()
    recs = body["details"]["recommendations"]
    actions = " | ".join(r["action"] for r in recs)
    assert "Block outbound traffic to 185.220.101.5" in actions
    assert "persistence" in actions.lower()
    assert all(r["requires_approval"] and r["executed"] is False and r["status"] == "PENDING" for r in recs)
    assert body["human_approval_status"] == "PENDING" and body["status"] == "RESPONSE_PROPOSED"
    assert body["recommended_action"] == recs[0]["action"]
    assert body["details"]["response"]["execution_mode"] == "simulation_only"


def test_domain_controller_incident_recommends_credential_reset(iso_client):
    inc = _incidents(iso_client)["dc"]
    recs = iso_client.post(f"/api/v1/incidents/{inc}/recommend").json()["details"]["recommendations"]
    assert any("Reset credentials" in r["action"] and "admin_svc" in r["action"] for r in recs)


def test_weak_evidence_recommends_more_investigation_not_containment():
    out = ResponseAgent().recommend({"id": "I", "severity": "CRITICAL"},
                                    [{"id": "a", "alert_title": "ransomware encryptor", "host": "H", "severity": "CRITICAL"}], None)
    assert len(out["recommendations"]) == 1
    assert "additional evidence" in out["recommendations"][0]["action"] and out["recommendations"][0]["impact"] == "NONE"


def test_approve_records_decision_audit_and_executes_nothing(iso_client):
    inc = _incidents(iso_client)["fin"]
    iso_client.post(f"/api/v1/incidents/{inc}/recommend")
    res = iso_client.post(f"/api/v1/incidents/{inc}/approve", json={"reviewer": "Chandresh", "reason": "Confirmed with log evidence"})
    assert res.status_code == 200
    body = res.json()
    assert body["human_approval_status"] == "APPROVED" and body["status"] == "RESPONSE_APPROVED"
    assert body["details"]["review"]["reviewer"] == "Chandresh" and "simulation_only" in body["details"]["review"]["execution"]
    assert all(r["status"] == "APPROVED" and r["executed"] is False for r in body["details"]["recommendations"])
    logs = iso_client.get("/api/v1/audit-logs", params={"target_id": inc, "action": "INCIDENT_APPROVED"}).json()
    assert logs and logs[0]["actor"] == "Chandresh"


def test_reject_works_and_decision_cannot_be_repeated(iso_client):
    inc = _incidents(iso_client)["dc"]
    iso_client.post(f"/api/v1/incidents/{inc}/recommend")
    assert iso_client.post(f"/api/v1/incidents/{inc}/reject", json={"reviewer": "K"}).json()["human_approval_status"] == "REJECTED"
    assert iso_client.post(f"/api/v1/incidents/{inc}/approve", json={"reviewer": "K"}).status_code == 409
    assert iso_client.post(f"/api/v1/incidents/{inc}/recommend").status_code == 409


def test_cannot_decide_without_recommendation_or_reviewer(iso_client):
    inc = _incidents(iso_client)["fin"]
    assert iso_client.post(f"/api/v1/incidents/{inc}/approve", json={"reviewer": "A"}).status_code == 409
    iso_client.post(f"/api/v1/incidents/{inc}/recommend")
    assert iso_client.post(f"/api/v1/incidents/{inc}/approve", json={}).status_code == 422
    assert iso_client.post(f"/api/v1/incidents/{inc}/approve", json={"reviewer": ""}).status_code == 422
    assert iso_client.post("/api/v1/incidents/NOPE/approve", json={"reviewer": "A"}).status_code == 404


def test_new_alert_resets_a_previous_approval(iso_client):
    inc = _incidents(iso_client)["dc"]
    iso_client.post(f"/api/v1/incidents/{inc}/recommend")
    iso_client.post(f"/api/v1/incidents/{inc}/approve", json={"reviewer": "A"})
    iso_client.post("/api/v1/alerts", json={"id": "ALT-NEW", "alert_title": "more", "host": "DC-PRIMARY-01", "timestamp": "2026-09-03T09:30:00Z"})
    iso_client.post("/api/v1/incidents/correlate")
    body = iso_client.get(f"/api/v1/incidents/{inc}").json()
    assert body["human_approval_status"] == "PENDING"
    assert iso_client.post(f"/api/v1/incidents/{inc}/approve", json={"reviewer": "A"}).status_code == 409  # stale
    assert iso_client.get("/api/v1/audit-logs", params={"action": "APPROVAL_RESET"}).json()
