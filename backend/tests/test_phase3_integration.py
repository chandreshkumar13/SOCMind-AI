"""Phase 3 regression tests: triage/enrichment status transitions, audit trail and safe errors.

Uses the isolated `iso_client` fixture (own temporary database per test).
"""
from collections import Counter

from app.main import app
from app.models.models import AlertModel


def _ingest(client, **fields):
    payload = {"alert_title": "Phase 3 test alert", "severity": "HIGH", **fields}
    res = client.post("/api/v1/alerts", json=payload)
    assert res.status_code == 201
    return res.json()["id"]


def _set_status(client, alert_id, new_status):
    db = client.session_factory()
    try:
        db.query(AlertModel).filter(AlertModel.id == alert_id).first().status = new_status
        db.commit()
    finally:
        db.close()


def test_new_alert_moves_to_triaged_then_enriched(iso_client):
    alert_id = _ingest(iso_client, destination_ip="185.220.101.5")
    assert iso_client.post(f"/api/v1/alerts/{alert_id}/triage").json()["alert"]["status"] == "TRIAGED"
    assert iso_client.post(f"/api/v1/alerts/{alert_id}/enrich").json()["alert"]["status"] == "ENRICHED"
    # Existing behaviour is preserved: triage may be re-run on an enriched alert.
    again = iso_client.post(f"/api/v1/alerts/{alert_id}/triage").json()
    assert again["alert"]["status"] == "TRIAGED"
    assert "enrichment" in again["alert"]["normalized_data"] and "triage" in again["alert"]["normalized_data"]


def test_closed_alert_stays_closed_for_triage_and_enrichment(iso_client):
    alert_id = _ingest(iso_client, destination_ip="185.220.101.5")
    iso_client.delete(f"/api/v1/alerts/{alert_id}")
    triage = iso_client.post(f"/api/v1/alerts/{alert_id}/triage")
    enrich = iso_client.post(f"/api/v1/alerts/{alert_id}/enrich")
    assert triage.status_code == enrich.status_code == 200
    assert triage.json()["alert"]["status"] == enrich.json()["alert"]["status"] == "CLOSED"
    assert iso_client.get(f"/api/v1/alerts/{alert_id}").json()["status"] == "CLOSED"
    # The analysis itself is still produced and stored
    assert triage.json()["triage_result"]["suspicion_score"] > 0
    assert enrich.json()["enrichment_result"]["summary"]["malicious"] == 1


def test_correlated_alert_is_not_moved_backwards(iso_client):
    alert_id = _ingest(iso_client)
    _set_status(iso_client, alert_id, "CORRELATED")
    assert iso_client.post(f"/api/v1/alerts/{alert_id}/triage").json()["alert"]["status"] == "CORRELATED"
    assert iso_client.post(f"/api/v1/alerts/{alert_id}/enrich").json()["alert"]["status"] == "CORRELATED"


def test_enrichment_contract_is_unchanged_and_additively_labelled(iso_client):
    alert_id = _ingest(iso_client, source_ip="10.0.0.5", destination_ip="185.220.101.5")
    body = iso_client.post(f"/api/v1/alerts/{alert_id}/enrich").json()
    result = body["enrichment_result"]
    assert set(body) == {"alert", "enrichment_result"}
    for key in ("agent", "status", "timestamp", "alert_id", "total_iocs_extracted", "summary", "iocs"):
        assert key in result
    assert set(result["summary"]) == {"malicious", "suspicious", "clean", "unknown"}
    assert {i["type"] for i in result["iocs"]} == {"IP"}
    assert {i["reputation"] for i in result["iocs"]} == {"CLEAN", "MALICIOUS"}
    assert result["verified"] is False and result["intel_mode"] == "mock"


def test_audit_trail_covers_ingest_triage_enrich_close_and_seed(iso_client):
    assert iso_client.post("/api/v1/alerts/seed").json()["inserted"] > 0
    alert_id = _ingest(iso_client)
    iso_client.post(f"/api/v1/alerts/{alert_id}/triage")
    iso_client.post(f"/api/v1/alerts/{alert_id}/enrich")
    iso_client.delete(f"/api/v1/alerts/{alert_id}")
    by_target = {l["action"] for l in iso_client.get("/api/v1/audit-logs", params={"target_id": alert_id}).json()}
    assert by_target == {"ALERT_INGESTED", "ALERT_TRIAGED", "ALERT_ENRICHED", "ALERT_CLOSED"}
    seeded = iso_client.get("/api/v1/audit-logs", params={"action": "ALERTS_SEEDED"}).json()
    assert len(seeded) == 1 and seeded[0]["target_id"] == "synthetic_alerts.json"
    # A second seed call inserts nothing and must not add another audit entry
    iso_client.post("/api/v1/alerts/seed")
    assert len(iso_client.get("/api/v1/audit-logs", params={"action": "ALERTS_SEEDED"}).json()) == 1


def test_rejected_duplicate_ingest_is_not_audited_twice(iso_client):
    payload = {"id": "DUP-1", "alert_title": "dup"}
    assert iso_client.post("/api/v1/alerts", json=payload).status_code == 201
    assert iso_client.post("/api/v1/alerts", json=payload).status_code == 409
    logs = iso_client.get("/api/v1/audit-logs", params={"target_id": "DUP-1", "action": "ALERT_INGESTED"}).json()
    assert len(logs) == 1


def test_audit_log_filters_and_details_are_structured(iso_client):
    alert_id = _ingest(iso_client, destination_ip="185.220.101.5")
    iso_client.post(f"/api/v1/alerts/{alert_id}/enrich")
    entry = iso_client.get("/api/v1/audit-logs", params={"action": "ALERT_ENRICHED"}).json()[0]
    assert entry["actor"] == "Enrichment Agent" and entry["details"]["summary"]["malicious"] == 1
    assert iso_client.get("/api/v1/audit-logs", params={"limit": 0}).status_code == 422


def test_internal_errors_are_not_exposed_to_clients(iso_client, monkeypatch):
    import app.api.v1.alerts_api as alerts_api

    def boom(db):
        raise RuntimeError("secret-internal-detail C:\\private\\path")

    monkeypatch.setattr(alerts_api, "seed_synthetic_alerts", boom)
    res = iso_client.post("/api/v1/alerts/seed")
    assert res.status_code == 500
    assert "secret-internal-detail" not in res.text and "private" not in res.text
    assert res.json()["error"] == "Internal Server Error"


def test_no_duplicate_routes_and_phase3_routes_registered():
    from app.api.v1 import alerts_api, audit_api, health

    leaf = Counter((m, r.path) for router in (health.router, alerts_api.router, audit_api.router)
                   for r in router.routes for m in r.methods)
    assert [k for k, n in leaf.items() if n > 1] == []
    paths = app.openapi()["paths"]
    for method, path in [("post", "/api/v1/alerts/{alert_id}/triage"), ("post", "/api/v1/alerts/{alert_id}/enrich"),
                         ("get", "/api/v1/audit-logs"), ("post", "/api/v1/alerts/seed")]:
        assert method in paths[path]
    # Phase 4+ endpoints must not be registered yet
    assert not any(p.startswith(("/api/v1/incidents", "/api/v1/pipeline")) for p in paths)
