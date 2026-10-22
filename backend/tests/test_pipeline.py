from app.agents.enrichment.enrichment_agent import EnrichmentAgent


def test_full_pipeline_end_to_end(iso_client):
    iso_client.post("/api/v1/alerts/seed")
    run = iso_client.post("/api/v1/pipeline/run").json()
    assert run["status"] == "completed" and run["alerts_in_scope"] == 10
    stages = {s["agent"]: s for s in run["stages"]}
    assert stages["Triage Agent"]["processed"] == 10 and stages["Enrichment Agent"]["processed"] == 10
    assert len(run["incidents_created"]) == 2 and stages["Investigation Agent"]["processed"] == 2
    assert stages["Response Agent"]["processed"] == 2 and run["incidents_awaiting_human_review"] == 2
    incs = iso_client.get("/api/v1/incidents").json()
    assert all(i["status"] == "RESPONSE_PROPOSED" and i["human_approval_status"] == "PENDING" and i["recommended_action"] for i in incs)
    # alerts carry triage + enrichment + incident link
    a = iso_client.get("/api/v1/alerts/ALT-2026-004").json()
    assert {"triage", "enrichment", "incident_id"} <= set(a["normalized_data"])


def test_pipeline_is_idempotent(iso_client):
    iso_client.post("/api/v1/alerts/seed")
    iso_client.post("/api/v1/pipeline/run")
    again = iso_client.post("/api/v1/pipeline/run").json()
    assert again["incidents_created"] == [] and again["incidents_updated"] == []
    assert all(s["processed"] == 0 for s in again["stages"])
    assert len(iso_client.get("/api/v1/incidents").json()) == 2


def test_pipeline_on_empty_database(iso_client):
    run = iso_client.post("/api/v1/pipeline/run").json()
    assert run["status"] == "completed" and run["alerts_in_scope"] == 0 and run["incidents_created"] == []
    assert "Insufficient" in run["message"]


def test_agent_failure_does_not_stop_the_pipeline(iso_client, monkeypatch):
    iso_client.post("/api/v1/alerts/seed")

    def boom(self, alert):
        raise RuntimeError("intel service down")
    monkeypatch.setattr(EnrichmentAgent, "enrich_alert", boom)
    run = iso_client.post("/api/v1/pipeline/run").json()
    stages = {s["agent"]: s for s in run["stages"]}
    assert run["status"] == "completed_with_errors"
    assert stages["Enrichment Agent"]["status"] == "failed" and "intel service down" in stages["Enrichment Agent"]["errors"][0]
    assert stages["Triage Agent"]["status"] == "success"
    assert len(run["incidents_created"]) == 2 and stages["Response Agent"]["processed"] == 2   # later stages still ran
    assert iso_client.get("/api/v1/audit-logs", params={"action": "AGENT_FAILED"}).json()


def test_pipeline_limited_to_given_alerts(iso_client):
    iso_client.post("/api/v1/alerts/seed")
    run = iso_client.post("/api/v1/pipeline/run", json={"alert_ids": ["ALT-2026-001"]}).json()
    assert run["alerts_in_scope"] == 1
    assert iso_client.post("/api/v1/pipeline/run", json={"window_hours": 0}).status_code == 422


def test_pipeline_skips_closed_alerts(iso_client):
    iso_client.post("/api/v1/alerts/seed")
    iso_client.delete("/api/v1/alerts/ALT-2026-001")
    run = iso_client.post("/api/v1/pipeline/run").json()
    assert run["alerts_in_scope"] == 9


def test_runs_and_agents_endpoints_reflect_real_activity(iso_client):
    iso_client.post("/api/v1/alerts/seed")
    iso_client.post("/api/v1/pipeline/run")
    runs = iso_client.get("/api/v1/pipeline/runs").json()
    assert len(runs) == 1 and runs[0]["stages"]
    agents = {a["name"]: a for a in iso_client.get("/api/v1/agents").json()}
    assert agents["Triage Agent"]["total_actions"] == 10 and agents["Triage Agent"]["last_action"] == "ALERT_TRIAGED"
    assert agents["Correlation Agent"]["total_actions"] == 2 and agents["Orchestrator"]["last_action"] == "PIPELINE_RUN"
    assert agents["Response Agent"]["total_actions"] == 2
