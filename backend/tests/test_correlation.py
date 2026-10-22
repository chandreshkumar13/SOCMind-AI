from sqlalchemy import create_engine, text, inspect
from app.agents.correlation.correlation_agent import CorrelationAgent
from app.db.session import ensure_columns


def A(i, ts, host=None, user=None, sip=None, dip=None, h=None, sev="MEDIUM"):
    return {"id": i, "timestamp": ts, "host": host, "username": user, "source_ip": sip, "destination_ip": dip,
            "file_hash": h, "severity": sev, "alert_title": f"alert {i}"}


def test_links_alerts_sharing_strong_entity_within_window():
    g = CorrelationAgent().correlate_alerts([
        A("a", "2026-09-03T08:00:00Z", host="H1", sev="HIGH"), A("b", "2026-09-03T09:00:00Z", host="h1", sev="CRITICAL"),
        A("c", "2026-09-03T09:00:00Z", host="OTHER")])
    assert len(g) == 1 and g[0]["alert_ids"] == ["a", "b"] and g[0]["severity"] == "CRITICAL"


def test_username_alone_does_not_link():
    assert CorrelationAgent().correlate_alerts([
        A("a", "2026-09-03T08:00:00Z", user="root", host="X"), A("b", "2026-09-03T08:05:00Z", user="root", host="Y")]) == []


def test_time_window_respected():
    assert CorrelationAgent().correlate_alerts([
        A("a", "2026-09-01T08:00:00Z", host="H"), A("b", "2026-09-03T08:00:00Z", host="H")], window_hours=24) == []


def test_transitive_linking_and_empty_and_single():
    g = CorrelationAgent().correlate_alerts([
        A("a", "2026-09-03T08:00:00Z", host="H1"), A("b", "2026-09-03T08:10:00Z", host="H1", dip="1.2.3.4"),
        A("c", "2026-09-03T08:20:00Z", host="H2", dip="1.2.3.4")])
    assert len(g) == 1 and g[0]["alert_count"] == 3
    assert CorrelationAgent().correlate_alerts([]) == []
    assert CorrelationAgent().correlate_alerts([A("a", "2026-09-03T08:00:00Z", host="H")]) == []


def test_seed_data_produces_two_incidents(iso_client):
    iso_client.post("/api/v1/alerts/seed")
    res = iso_client.post("/api/v1/incidents/correlate").json()
    assert res["groups_found"] == 2 and len(res["created"]) == 2
    incs = iso_client.get("/api/v1/incidents").json()
    sets = sorted(sorted(i["correlated_alert_ids"]) for i in incs)
    assert sets == [["ALT-2026-001", "ALT-2026-004", "ALT-2026-010"], ["ALT-2026-006", "ALT-2026-009"]]
    assert all(i["human_approval_status"] == "PENDING" for i in incs)
    assert iso_client.get("/api/v1/alerts/ALT-2026-004").json()["status"] == "CORRELATED"


def test_correlation_is_idempotent(iso_client):
    iso_client.post("/api/v1/alerts/seed")
    iso_client.post("/api/v1/incidents/correlate")
    again = iso_client.post("/api/v1/incidents/correlate").json()
    assert again["created"] == [] and again["updated"] == [] and len(again["unchanged"]) == 2
    assert len(iso_client.get("/api/v1/incidents").json()) == 2


def test_insufficient_evidence_message_and_no_alerts(iso_client):
    res = iso_client.post("/api/v1/incidents/correlate").json()
    assert res["groups_found"] == 0 and "Insufficient" in res["message"]


def test_new_alert_joins_existing_incident(iso_client):
    iso_client.post("/api/v1/alerts/seed")
    iso_client.post("/api/v1/incidents/correlate")
    iso_client.post("/api/v1/alerts", json={"id": "ALT-X", "alert_title": "later", "host": "DC-PRIMARY-01",
                                            "timestamp": "2026-09-03T09:10:00Z", "severity": "critical"})
    res = iso_client.post("/api/v1/incidents/correlate").json()
    assert len(res["updated"]) == 1 and res["created"] == []
    inc = iso_client.get(f"/api/v1/incidents/{res['updated'][0]}").json()
    assert "ALT-X" in inc["correlated_alert_ids"] and inc["severity"] == "CRITICAL"
    assert {a["id"] for a in inc["alerts"]} >= {"ALT-X", "ALT-2026-006"}


def test_closed_alerts_are_not_correlated(iso_client):
    iso_client.post("/api/v1/alerts/seed")
    iso_client.delete("/api/v1/alerts/ALT-2026-009")
    res = iso_client.post("/api/v1/incidents/correlate").json()
    assert res["groups_found"] == 1


def test_incident_404_and_invalid_window(iso_client):
    assert iso_client.get("/api/v1/incidents/NOPE").status_code == 404
    assert iso_client.post("/api/v1/incidents/correlate", json={"window_hours": 0}).status_code == 422


def test_old_database_is_upgraded_in_place(tmp_path):
    eng = create_engine(f"sqlite:///{tmp_path/'old.db'}")
    with eng.begin() as c:
        c.execute(text("CREATE TABLE incidents (id VARCHAR PRIMARY KEY, title VARCHAR)"))
    ensure_columns(eng)
    ensure_columns(eng)  # running twice must be harmless
    assert "details" in {c["name"] for c in inspect(eng).get_columns("incidents")}


def test_incident_title_keeps_original_host_capitalisation(iso_client):
    iso_client.post("/api/v1/alerts/seed")
    iso_client.post("/api/v1/incidents/correlate")
    titles = " ".join(i["title"] for i in iso_client.get("/api/v1/incidents").json())
    assert "DC-PRIMARY-01" in titles and "FINANCE-WKS-042" in titles
