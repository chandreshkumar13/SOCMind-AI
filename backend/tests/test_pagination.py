"""Pagination totals (C11): list endpoints report the number of matching records, not just the page, so the UI can say
'showing 100 of 240' and load the rest with the same filters."""


def _ingest(client, alert_id, severity="LOW", minute=0):
    body = {"id": alert_id, "alert_title": f"Page test {alert_id}", "source": "CrowdStrike EDR", "severity": severity,
            "host": f"PG-HOST-{alert_id}", "timestamp": f"2026-09-03T08:{minute:02d}:00Z"}
    assert client.post("/api/v1/alerts", json=body).status_code == 201


def test_alert_list_reports_the_total_number_of_matches_on_every_page(iso_client):
    for i in range(5):
        _ingest(iso_client, f"PG-{i}", minute=i)
    first = iso_client.get("/api/v1/alerts?limit=2")
    assert first.status_code == 200
    assert first.headers["X-Total-Count"] == "5"
    assert len(first.json()) == 2
    last = iso_client.get("/api/v1/alerts?limit=2&offset=4")
    assert last.headers["X-Total-Count"] == "5" and len(last.json()) == 1


def test_the_total_follows_the_filters_not_the_whole_table(iso_client):
    _ingest(iso_client, "PG-H1", severity="HIGH", minute=1)
    _ingest(iso_client, "PG-H2", severity="HIGH", minute=2)
    _ingest(iso_client, "PG-L1", severity="LOW", minute=3)
    high = iso_client.get("/api/v1/alerts?severity=HIGH&limit=1")
    assert high.headers["X-Total-Count"] == "2" and len(high.json()) == 1


def test_the_total_is_exposed_to_the_browser_through_cors(iso_client):
    _ingest(iso_client, "PG-CORS")
    response = iso_client.get("/api/v1/alerts", headers={"Origin": "http://localhost:5173"})
    exposed = response.headers.get("access-control-expose-headers", "")
    assert "X-Total-Count" in exposed


def test_the_incident_list_reports_its_total_too(iso_client):
    for i, minute in enumerate((0, 5)):
        body = {"id": f"PGI-{i}", "alert_title": "Incident page", "source": "CrowdStrike EDR", "severity": "HIGH",
                "host": "PGI-HOST", "timestamp": f"2026-09-03T08:{minute:02d}:00Z"}
        assert iso_client.post("/api/v1/alerts", json=body).status_code == 201
    assert iso_client.post("/api/v1/incidents/correlate").status_code == 200
    response = iso_client.get("/api/v1/incidents?limit=1")
    assert response.headers["X-Total-Count"] == "1" and len(response.json()) == 1
