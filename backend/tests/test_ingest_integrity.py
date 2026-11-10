"""Duplicate ingestion (C14): a duplicate is refused with 409, including when two requests race for the same alert ID.

The ID is the primary key, so the database itself rejects the second insert. A request that loses that race must receive a
409, not an unhandled error. Uniqueness of (source, external_alert_id) is checked by the application before the insert; the
database does not enforce it, because adding a unique index would be a schema change that is not made silently.
"""
from app.api.v1 import alerts_api


def _alert(alert_id, **extra):
    return {"id": alert_id, "alert_title": "Ingest integrity", "source": "CrowdStrike EDR", "severity": "LOW",
            "host": "INGEST-HOST", "timestamp": "2026-09-03T08:00:00Z", **extra}


def test_a_duplicate_id_that_loses_the_race_after_the_check_is_refused_with_409(iso_client, monkeypatch):
    assert iso_client.post("/api/v1/alerts", json=_alert("RACE-1")).status_code == 201
    # Simulate the losing side of a race: this request's check ran before the other request stored the alert
    monkeypatch.setattr(alerts_api, "_already_stored", lambda db, alert_id: False)
    res = iso_client.post("/api/v1/alerts", json=_alert("RACE-1"))
    assert res.status_code == 409, res.text
    assert "already exists" in res.json()["detail"]
    monkeypatch.undo()
    stored = iso_client.get("/api/v1/alerts", params={"search": "RACE-1", "limit": 100}).json()
    assert [a["id"] for a in stored] == ["RACE-1"]          # exactly one row, the first one


def test_the_same_upstream_alert_cannot_be_ingested_twice(iso_client):
    assert iso_client.post("/api/v1/alerts", json=_alert("UP-1", external_alert_id="EDR-99")).status_code == 201
    res = iso_client.post("/api/v1/alerts", json=_alert("UP-2", external_alert_id="EDR-99"))
    assert res.status_code == 409
    assert "EDR-99" in res.json()["detail"]


def test_the_same_upstream_id_from_a_different_source_is_a_different_alert(iso_client):
    assert iso_client.post("/api/v1/alerts", json=_alert("SRC-1", external_alert_id="EDR-7")).status_code == 201
    res = iso_client.post("/api/v1/alerts", json=_alert("SRC-2", source="Splunk SIEM", external_alert_id="EDR-7"))
    assert res.status_code == 201
