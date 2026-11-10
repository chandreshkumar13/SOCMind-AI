"""Closed alerts (C5): a closed alert leaves the incidents that held it and can never silently re-enter an active incident.

The alert record and its audit history are kept. Incident membership, incident status and the counts shown to analysts stay
consistent with the alerts that are actually active.
"""
from app.models.models import AlertModel, IncidentModel


def _ingest(client, alert_id, host, timestamp):
    return client.post("/api/v1/alerts", json={"id": alert_id, "alert_title": "Closed alert test", "source": "CrowdStrike EDR",
                                               "severity": "LOW", "host": host, "timestamp": timestamp})


def _two_alert_incident(client):
    assert _ingest(client, "CL-1", "CL-HOST", "2026-09-03T08:00:00Z").status_code == 201
    assert _ingest(client, "CL-2", "CL-HOST", "2026-09-03T08:05:00Z").status_code == 201
    assert client.post("/api/v1/incidents/correlate").status_code == 200
    return client.get("/api/v1/incidents").json()[0]["id"]


def _incident(client, inc_id):
    return client.get(f"/api/v1/incidents/{inc_id}").json()


def _edit(client, model, row_id, change):
    db = client.session_factory()
    try:
        row = db.query(model).filter(getattr(model, "id") == row_id).one()
        change(row)
        db.commit()
    finally:
        db.close()


def test_closing_an_alert_removes_it_from_its_incident_and_keeps_the_record(iso_client):
    inc = _two_alert_incident(iso_client)
    assert iso_client.delete("/api/v1/alerts/CL-1").status_code == 200
    body = _incident(iso_client, inc)
    assert body["correlated_alert_ids"] == ["CL-2"]
    closed = body["details"]["closed_alerts"]
    assert [c["alert_id"] for c in closed] == ["CL-1"] and closed[0]["closed_at"].endswith("Z")
    assert body["details"]["investigation_stale"] is True and body["details"]["recommendations_stale"] is True
    assert any(r["alert_id"] == "CL-1" and "closed" in r["change"] for r in body["details"]["stale_reasons"])
    membership = iso_client.get("/api/v1/audit-logs", params={"target_id": inc, "action": "INCIDENT_MEMBERSHIP_CHANGED"}).json()
    assert len(membership) == 1 and membership[0]["details"]["removed_alert"] == "CL-1"
    assert iso_client.get("/api/v1/alerts/CL-1").json()["status"] == "CLOSED"       # the alert itself is kept


def test_closing_the_last_alert_closes_the_incident_and_hides_it_from_the_active_list(iso_client):
    inc = _two_alert_incident(iso_client)
    iso_client.delete("/api/v1/alerts/CL-1")
    iso_client.delete("/api/v1/alerts/CL-2")
    assert _incident(iso_client, inc)["status"] == "CLOSED"
    assert inc not in [i["id"] for i in iso_client.get("/api/v1/incidents").json()]
    assert [i["id"] for i in iso_client.get("/api/v1/incidents", params={"status": "CLOSED"}).json()] == [inc]
    stats = iso_client.get("/api/v1/stats").json()
    assert stats["incidents"]["total"] == 0 and stats["incidents"]["closed"] == 1


def test_a_decided_incident_loses_its_decision_when_one_of_its_alerts_closes(iso_client):
    inc = _two_alert_incident(iso_client)
    assert iso_client.post(f"/api/v1/incidents/{inc}/recommend").status_code == 200
    assert iso_client.post(f"/api/v1/incidents/{inc}/approve", json={"reviewer": "Analyst A"}).status_code == 200
    iso_client.delete("/api/v1/alerts/CL-1")
    body = _incident(iso_client, inc)
    assert body["human_approval_status"] == "PENDING"
    assert body["details"]["review_history"][0]["review"]["decision"] == "APPROVED"
    assert "alert CL-1 was closed" in body["details"]["review_history"][0]["superseded_by"]


def test_a_new_alert_for_the_same_host_does_not_re_enter_a_closed_incident(iso_client):
    inc = _two_alert_incident(iso_client)
    iso_client.delete("/api/v1/alerts/CL-1")
    iso_client.delete("/api/v1/alerts/CL-2")
    assert _ingest(iso_client, "CL-3", "CL-HOST", "2026-09-03T08:10:00Z").status_code == 201
    assert iso_client.post("/api/v1/incidents/correlate").status_code == 200
    assert _incident(iso_client, inc)["correlated_alert_ids"] == []
    assert _incident(iso_client, inc)["status"] == "CLOSED"
    assert iso_client.get("/api/v1/incidents").json() == []        # one active alert is not an incident


def test_a_closed_alert_id_cannot_be_ingested_again(iso_client):
    assert _ingest(iso_client, "CL-REUSE", "CL-HOST", "2026-09-03T08:00:00Z").status_code == 201
    iso_client.delete("/api/v1/alerts/CL-REUSE")
    assert _ingest(iso_client, "CL-REUSE", "CL-HOST", "2026-09-03T08:00:00Z").status_code == 409


def test_correlation_never_re_adds_a_closed_alert_held_by_older_data(iso_client):
    inc = _two_alert_incident(iso_client)
    _edit(iso_client, AlertModel, "CL-1", lambda row: setattr(row, "status", "CLOSED"))    # closed, but still listed by the incident
    assert _ingest(iso_client, "CL-4", "CL-HOST", "2026-09-03T08:12:00Z").status_code == 201
    assert iso_client.post("/api/v1/incidents/correlate").status_code == 200
    assert "CL-1" not in _incident(iso_client, inc)["correlated_alert_ids"]
    assert set(_incident(iso_client, inc)["correlated_alert_ids"]) == {"CL-2", "CL-4"}


def test_investigation_excludes_a_closed_alert_still_listed_by_older_data(iso_client):
    inc = _two_alert_incident(iso_client)
    _edit(iso_client, AlertModel, "CL-1", lambda row: setattr(row, "status", "CLOSED"))
    res = iso_client.post(f"/api/v1/incidents/{inc}/investigate")
    assert res.status_code == 200
    refs = [e["ref"] for e in res.json()["details"]["investigation"]["timeline"] if e["type"] == "alert"]
    assert refs == ["CL-2"]


def test_a_closed_incident_cannot_be_investigated_recommended_or_decided(iso_client):
    inc = _two_alert_incident(iso_client)
    iso_client.delete("/api/v1/alerts/CL-1")
    iso_client.delete("/api/v1/alerts/CL-2")
    assert iso_client.post(f"/api/v1/incidents/{inc}/investigate").status_code == 409
    assert iso_client.post(f"/api/v1/incidents/{inc}/recommend").status_code == 409
    assert iso_client.post(f"/api/v1/incidents/{inc}/approve", json={"reviewer": "Analyst A"}).status_code == 409
    assert iso_client.post(f"/api/v1/incidents/{inc}/simulate", json={"reviewer": "Analyst A"}).status_code == 409
