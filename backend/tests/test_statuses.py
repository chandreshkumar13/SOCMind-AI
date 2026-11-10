"""Status and ordering consistency (C15).

Alert statuses only move forward (NEW -> TRIAGED -> ENRICHED -> CORRELATED -> INVESTIGATING, and CLOSED on closing), so a later
step never makes an earlier one look undone. Lists are sorted with a deterministic tie-breaker, agent status is derived from
recorded activity rather than a constant, and the dashboard counts match the stored records.
"""


def _ingest(client, alert_id, timestamp, host="STATUS-HOST"):
    return client.post("/api/v1/alerts", json={"id": alert_id, "alert_title": "Status test", "source": "CrowdStrike EDR",
                                               "severity": "LOW", "host": host, "timestamp": timestamp})


def _status(client, alert_id):
    return client.get(f"/api/v1/alerts/{alert_id}").json()["status"]


def test_triage_never_moves_an_enriched_alert_back_to_triaged(iso_client):
    assert _ingest(iso_client, "ST-1", "2026-09-03T08:00:00Z").status_code == 201
    assert iso_client.post("/api/v1/alerts/ST-1/triage").status_code == 200
    assert iso_client.post("/api/v1/alerts/ST-1/enrich").status_code == 200
    assert _status(iso_client, "ST-1") == "ENRICHED"
    assert iso_client.post("/api/v1/alerts/ST-1/triage").status_code == 200        # re-running triage
    assert _status(iso_client, "ST-1") == "ENRICHED"


def test_enrichment_never_moves_a_correlated_alert_back(iso_client):
    assert _ingest(iso_client, "ST-2", "2026-09-03T08:00:00Z").status_code == 201
    assert _ingest(iso_client, "ST-3", "2026-09-03T08:02:00Z").status_code == 201
    assert iso_client.post("/api/v1/incidents/correlate").status_code == 200
    assert _status(iso_client, "ST-2") == "CORRELATED"
    assert iso_client.post("/api/v1/alerts/ST-2/enrich").status_code == 200
    assert _status(iso_client, "ST-2") == "CORRELATED"


def test_alerts_with_the_same_time_are_listed_in_a_fixed_order(iso_client):
    assert _ingest(iso_client, "TIE-A", "2026-09-03T08:00:00Z").status_code == 201
    assert _ingest(iso_client, "TIE-B", "2026-09-03T08:00:00Z").status_code == 201
    first = [a["id"] for a in iso_client.get("/api/v1/alerts").json()]
    second = [a["id"] for a in iso_client.get("/api/v1/alerts").json()]
    assert first == second == ["TIE-B", "TIE-A"]                     # newest first, ties broken by ID (descending)


def test_agent_status_is_derived_from_recorded_activity_not_a_constant(iso_client):
    statuses = {a["name"]: a["status"] for a in iso_client.get("/api/v1/agents").json()}
    assert "READY" not in statuses.values()
    assert set(statuses.values()) <= {"IDLE", "ACTIVE", "ATTENTION"}
    assert all(s == "IDLE" for s in statuses.values())              # no activity recorded on a fresh database
    assert _ingest(iso_client, "AG-1", "2026-09-03T08:00:00Z").status_code == 201
    assert iso_client.post("/api/v1/alerts/AG-1/triage").status_code == 200
    statuses = {a["name"]: a["status"] for a in iso_client.get("/api/v1/agents").json()}
    assert statuses["Triage Agent"] == "ACTIVE"
    assert statuses["Enrichment Agent"] == "IDLE"


def test_the_dashboard_counts_open_alerts_separately_from_closed_ones(iso_client):
    assert _ingest(iso_client, "OPEN-1", "2026-09-03T08:00:00Z").status_code == 201
    assert _ingest(iso_client, "OPEN-2", "2026-09-03T08:01:00Z").status_code == 201
    assert iso_client.delete("/api/v1/alerts/OPEN-2").status_code == 200
    stats = iso_client.get("/api/v1/stats").json()
    assert stats["alerts"]["total"] == 2
    assert stats["alerts"]["open"] == 1
    assert stats["alerts"]["by_status"]["CLOSED"] == 1
