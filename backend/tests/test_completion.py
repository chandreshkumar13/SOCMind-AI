"""Completion-pass coverage: timestamps, duplicate detection, input limits, failure containment, threat-intel mode,
statistics/configuration endpoints, the approval -> simulation lifecycle and concurrency guards.

Uses the isolated `iso_client` fixture (own temporary database per test); nothing touches socmind.db.
"""
import json

import pytest

from app.agents.enrichment.enrichment_agent import EnrichmentAgent
from app.agents.triage.triage_agent import TriageAgent
from app.core.config import settings
from app.models.models import AlertModel, IncidentModel
from app.services.incident_service import DecisionError, review_incident, simulate_response


def _pipeline(client):
    client.post("/api/v1/alerts/seed")
    return client.post("/api/v1/pipeline/run").json()


def _finance_id(client):
    return next(i["id"] for i in client.get("/api/v1/incidents").json() if "ALT-2026-001" in i["correlated_alert_ids"])


def _approved(client, reviewer="Analyst A"):
    _pipeline(client)
    inc = _finance_id(client)
    assert client.post(f"/api/v1/incidents/{inc}/approve", json={"reviewer": reviewer}).status_code == 200
    return inc


# ------------------------------------------------------------------ timestamps
def test_offset_timestamps_are_converted_to_utc_on_ingest(iso_client):
    res = iso_client.post("/api/v1/alerts", json={"id": "TZ-1", "alert_title": "tz", "timestamp": "2026-09-03T00:00:00+05:30"})
    assert res.status_code == 201
    assert res.json()["timestamp"] == "2026-09-02T18:30:00Z"
    assert iso_client.post("/api/v1/alerts", json={"id": "TZ-2", "alert_title": "tz", "timestamp": "2026-09-03T08:00:00Z"}).json()["timestamp"] == "2026-09-03T08:00:00Z"


def test_api_timestamps_are_explicit_utc(iso_client):
    _pipeline(iso_client)
    alert = iso_client.get("/api/v1/alerts/ALT-2026-001").json()
    assert all(alert[k].endswith("Z") for k in ("timestamp", "created_at", "updated_at"))
    assert iso_client.get("/api/v1/incidents").json()[0]["created_at"].endswith("Z")
    assert iso_client.get("/api/v1/audit-logs").json()[0]["timestamp"].endswith("Z")
    inc = iso_client.get(f"/api/v1/incidents/{_finance_id(iso_client)}").json()
    assert inc["details"]["correlation"]["first_seen"].endswith("Z")


# ------------------------------------------------------------------ duplicate detection and validation
def test_same_upstream_alert_is_not_ingested_twice(iso_client):
    first = {"id": "D-1", "alert_title": "x", "source": "Splunk", "external_alert_id": "SPL-9"}
    assert iso_client.post("/api/v1/alerts", json=first).status_code == 201
    dup = iso_client.post("/api/v1/alerts", json={**first, "id": "D-2"})
    assert dup.status_code == 409 and "D-1" in dup.json()["detail"]
    assert iso_client.post("/api/v1/alerts", json={**first, "id": "D-3", "source": "CrowdStrike"}).status_code == 201   # other system
    assert iso_client.post("/api/v1/alerts", json={"id": "D-4", "alert_title": "x", "source": "Splunk"}).status_code == 201   # no upstream id
    assert iso_client.get("/api/v1/alerts/D-2").status_code == 404                                                   # nothing was stored


@pytest.mark.parametrize("field,length", [("alert_title", 501), ("command_line", 10001), ("id", 101), ("host", 256), ("description", 10001)])
def test_oversized_fields_are_rejected(iso_client, field, length):
    payload = {"alert_title": "t", field: "a" * length}
    assert iso_client.post("/api/v1/alerts", json=payload).status_code == 422


def test_fields_at_the_limit_are_accepted(iso_client):
    assert iso_client.post("/api/v1/alerts", json={"alert_title": "a" * 500, "command_line": "c" * 10000}).status_code == 201


# ------------------------------------------------------------------ failure containment
@pytest.mark.parametrize("agent_cls,method,path,agent_name,stored_key", [
    (EnrichmentAgent, "enrich_alert", "enrich", "Enrichment Agent", "enrichment"),
    (TriageAgent, "analyze_alert", "triage", "Triage Agent", "triage"),
])
def test_agent_failure_on_an_endpoint_is_contained_and_audited(iso_client, monkeypatch, agent_cls, method, path, agent_name, stored_key):
    iso_client.post("/api/v1/alerts", json={"id": "F-1", "alert_title": "f"})

    def boom(self, alert):
        raise RuntimeError("provider timeout C:\\secret\\path")
    monkeypatch.setattr(agent_cls, method, boom)
    res = iso_client.post(f"/api/v1/alerts/F-1/{path}")
    assert res.status_code == 502
    assert "RuntimeError" in res.json()["detail"] and "secret" not in res.text and "Traceback" not in res.text
    alert = iso_client.get("/api/v1/alerts/F-1").json()
    assert alert["status"] == "NEW" and stored_key not in alert["normalized_data"]            # nothing half-written
    failures = iso_client.get("/api/v1/audit-logs", params={"action": "AGENT_FAILED", "target_id": "F-1"}).json()
    assert len(failures) == 1 and failures[0]["actor"] == agent_name


def test_failed_enrichment_is_retried_by_the_next_pipeline_run(iso_client, monkeypatch):
    iso_client.post("/api/v1/alerts/seed")
    with monkeypatch.context() as m:
        m.setattr(EnrichmentAgent, "enrich_alert", lambda self, alert: (_ for _ in ()).throw(RuntimeError("down")))
        assert iso_client.post("/api/v1/pipeline/run").json()["outcome"] == "partial"
    again = iso_client.post("/api/v1/pipeline/run").json()
    stages = {s["agent"]: s for s in again["stages"]}
    assert stages["Enrichment Agent"]["processed"] == 10 and stages["Triage Agent"]["processed"] == 0
    assert again["outcome"] == "success"
    assert all("enrichment" in a["normalized_data"] for a in iso_client.get("/api/v1/alerts", params={"limit": 100}).json())


def test_run_report_lists_the_items_each_stage_handled(iso_client):
    run = _pipeline(iso_client)
    stages = {s["agent"]: s for s in run["stages"]}
    assert len(stages["Triage Agent"]["items"]) == 10 and "ALT-2026-001" in stages["Triage Agent"]["items"]
    assert sorted(stages["Correlation Agent"]["items"]) == sorted(run["incidents_created"])
    assert all(len(s["items"]) == s["processed"] for s in run["stages"])


# ------------------------------------------------------------------ threat-intel mode
def test_without_a_provider_iocs_are_extracted_but_not_looked_up(iso_client, monkeypatch):
    monkeypatch.setattr(settings, "THREAT_INTEL_MOCK_MODE", False)
    iso_client.post("/api/v1/alerts", json={"id": "U-1", "alert_title": "u", "destination_ip": "185.220.101.5", "source_ip": "10.0.0.5"})
    body = iso_client.post("/api/v1/alerts/U-1/enrich").json()
    enr = body["enrichment_result"]
    assert body["alert"]["status"] == "ENRICHED" and enr["intel_mode"] == "unavailable" and enr["lookup_performed"] is False
    assert enr["total_iocs_extracted"] == 2 and enr["summary"] == {"malicious": 0, "suspicious": 0, "clean": 0, "unknown": 2}
    assert {i["reputation"] for i in enr["iocs"]} == {"UNKNOWN"} and {i["provider"] for i in enr["iocs"]} == {"none"}
    assert "not checked" in enr["disclaimer"]
    audit = iso_client.get("/api/v1/audit-logs", params={"action": "ALERT_ENRICHED", "target_id": "U-1"}).json()[0]
    assert audit["details"]["intel_mode"] == "unavailable"


def test_pipeline_without_a_provider_reports_no_intelligence_findings(iso_client, monkeypatch):
    monkeypatch.setattr(settings, "THREAT_INTEL_MOCK_MODE", False)
    _pipeline(iso_client)
    inv = iso_client.get(f"/api/v1/incidents/{_finance_id(iso_client)}").json()["details"]["investigation"]
    assert not any(f["type"] == "mock_intel" for f in inv["findings"])


def test_default_mode_is_labelled_mock(iso_client):
    iso_client.post("/api/v1/alerts", json={"id": "M-1", "alert_title": "m", "destination_ip": "185.220.101.5"})
    enr = iso_client.post("/api/v1/alerts/M-1/enrich").json()["enrichment_result"]
    assert enr["intel_mode"] == "mock" and enr["summary"]["malicious"] == 1 and enr["verified"] is False


# ------------------------------------------------------------------ stats and config
def test_stats_report_true_totals_beyond_the_list_page_size(iso_client):
    db = iso_client.session_factory()
    db.add_all([AlertModel(id=f"BULK-{i:03d}", source="Test", alert_title="bulk", severity="LOW", status="NEW") for i in range(130)])
    db.commit()
    db.close()
    stats = iso_client.get("/api/v1/stats").json()
    assert stats["alerts"]["total"] == 130 and stats["alerts"]["by_status"] == {"NEW": 130} and stats["alerts"]["by_severity"] == {"LOW": 130}
    assert len(iso_client.get("/api/v1/alerts", params={"limit": 100}).json()) == 100            # the list itself is paginated


def test_stats_track_incidents_and_review_state(iso_client):
    _pipeline(iso_client)
    stats = iso_client.get("/api/v1/stats").json()
    assert stats["incidents"]["total"] == 2 and stats["incidents"]["awaiting_human_review"] == 2
    assert stats["incidents"]["by_status"] == {"RESPONSE_PROPOSED": 2} and stats["audit_entries"] > 10
    iso_client.post(f"/api/v1/incidents/{_finance_id(iso_client)}/reject", json={"reviewer": "A"})
    assert iso_client.get("/api/v1/stats").json()["incidents"]["awaiting_human_review"] == 1


def test_config_is_truthful_and_contains_no_secrets(iso_client, monkeypatch):
    monkeypatch.setattr(settings, "LLM_API_KEY", "sk-should-never-appear")
    monkeypatch.setattr(settings, "DATABASE_URL", "sqlite:///C:/private/dir/socmind.db")
    text = iso_client.get("/api/v1/config").text
    cfg = json.loads(text)
    assert cfg["execution_mode"] == "simulation_only" and cfg["authentication"]["enabled"] is False
    assert cfg["threat_intel"]["mode"] == "mock" and cfg["threat_intel"]["live_provider_implemented"] is False
    assert cfg["llm"]["used_by_agents"] is False and cfg["database_engine"] == "sqlite"
    assert "sk-should-never-appear" not in text and "private" not in text and "API_KEY" not in text
    monkeypatch.setattr(settings, "THREAT_INTEL_MOCK_MODE", False)
    assert iso_client.get("/api/v1/config").json()["threat_intel"]["mode"] == "unavailable"


# ------------------------------------------------------------------ approval -> simulation lifecycle
def test_investigation_states_where_its_logs_came_from(iso_client):
    _pipeline(iso_client)
    src = iso_client.get(f"/api/v1/incidents/{_finance_id(iso_client)}").json()["details"]["investigation"]["log_source"]
    assert src["type"] == "synthetic_sample_file" and src["path"].endswith("sample_logs.json") and "no SIEM" in src["note"]


def test_approved_is_not_executed_and_simulation_is_explicit(iso_client):
    inc = _approved(iso_client)
    approved = iso_client.get(f"/api/v1/incidents/{inc}").json()
    assert approved["status"] == "RESPONSE_APPROVED" and "simulation" not in approved["details"]
    assert all(r["simulation_status"] == "NOT_RUN" and r["executed"] is False for r in approved["details"]["recommendations"])

    res = iso_client.post(f"/api/v1/incidents/{inc}/simulate", json={"reviewer": "Analyst B", "reason": "dry run"})
    assert res.status_code == 200
    body = res.json()
    assert body["status"] == "RESPONSE_SIMULATED" and body["human_approval_status"] == "APPROVED"
    sim = body["details"]["simulation"]
    assert sim["mode"] == "simulation" and sim["simulated_by"] == "Analyst B" and sim["simulated_at"].endswith("Z")
    assert len(sim["actions"]) == len(body["details"]["recommendations"]) and "No command was run" in sim["actions"][0]["outcome"]
    assert all(r["executed"] is False and r["simulation_status"] == "SIMULATED" for r in body["details"]["recommendations"])
    log = iso_client.get("/api/v1/audit-logs", params={"action": "RESPONSE_SIMULATED", "target_id": inc}).json()
    assert len(log) == 1 and log[0]["actor"] == "Analyst B" and log[0]["details"]["executed"] is False
    assert "EXECUTED" not in json.dumps(body)


def test_simulation_requires_a_fresh_approval_and_happens_once(iso_client):
    _pipeline(iso_client)
    inc = _finance_id(iso_client)
    assert iso_client.post(f"/api/v1/incidents/{inc}/simulate", json={"reviewer": "A"}).status_code == 409        # not approved yet
    iso_client.post(f"/api/v1/incidents/{inc}/reject", json={"reviewer": "A"})
    assert iso_client.post(f"/api/v1/incidents/{inc}/simulate", json={"reviewer": "A"}).status_code == 409        # rejected
    assert iso_client.post("/api/v1/incidents/NOPE/simulate", json={"reviewer": "A"}).status_code == 404

    other = next(i["id"] for i in iso_client.get("/api/v1/incidents").json() if i["id"] != inc)
    iso_client.post(f"/api/v1/incidents/{other}/approve", json={"reviewer": "A"})
    assert iso_client.post(f"/api/v1/incidents/{other}/simulate", json={}).status_code == 422                       # actor required
    assert iso_client.post(f"/api/v1/incidents/{other}/simulate", json={"reviewer": "A"}).status_code == 200
    again = iso_client.post(f"/api/v1/incidents/{other}/simulate", json={"reviewer": "A"})
    assert again.status_code == 409 and "already simulated" in again.json()["detail"]
    assert len(iso_client.get("/api/v1/audit-logs", params={"action": "RESPONSE_SIMULATED"}).json()) == 1


def test_a_new_alert_voids_the_decision_and_keeps_it_as_history(iso_client):
    inc = _approved(iso_client)
    iso_client.post(f"/api/v1/incidents/{inc}/simulate", json={"reviewer": "A"})
    iso_client.post("/api/v1/alerts", json={"id": "LATE-1", "alert_title": "late", "host": "FINANCE-WKS-042", "timestamp": "2026-09-03T10:00:00Z"})
    iso_client.post("/api/v1/incidents/correlate")
    body = iso_client.get(f"/api/v1/incidents/{inc}").json()
    assert body["human_approval_status"] == "PENDING" and body["status"] == "OPEN"
    assert "review" not in body["details"] and "simulation" not in body["details"]
    (old,) = body["details"]["review_history"]
    assert old["review"]["decision"] == "APPROVED" and old["simulation"]["status"] == "SIMULATED" and old["superseded_at"].endswith("Z")
    assert iso_client.post(f"/api/v1/incidents/{inc}/simulate", json={"reviewer": "A"}).status_code == 409


def test_failed_decisions_leave_no_audit_entry(iso_client):
    inc = _approved(iso_client)
    for _ in range(2):
        assert iso_client.post(f"/api/v1/incidents/{inc}/reject", json={"reviewer": "B"}).status_code == 409
    assert len(iso_client.get("/api/v1/audit-logs", params={"target_id": inc, "action": "INCIDENT_APPROVED"}).json()) == 1
    assert iso_client.get("/api/v1/audit-logs", params={"target_id": inc, "action": "INCIDENT_REJECTED"}).json() == []


def test_concurrent_decisions_cannot_both_win(iso_client):
    _pipeline(iso_client)
    inc_id = _finance_id(iso_client)
    iso_client.post(f"/api/v1/incidents/{inc_id}/recommend")
    a, b = iso_client.session_factory(), iso_client.session_factory()
    try:
        stale = a.query(IncidentModel).filter(IncidentModel.id == inc_id).one()          # loaded while still PENDING
        assert stale.human_approval_status == "PENDING"
        review_incident(b, b.query(IncidentModel).filter(IncidentModel.id == inc_id).one(), "APPROVED", "First")
        with pytest.raises(DecisionError):
            review_incident(a, stale, "REJECTED", "Second")                              # would have passed the old check-then-write
    finally:
        a.close()
        b.close()
    final = iso_client.get(f"/api/v1/incidents/{inc_id}").json()
    assert final["human_approval_status"] == "APPROVED" and final["details"]["review"]["reviewer"] == "First"
    assert iso_client.get("/api/v1/audit-logs", params={"target_id": inc_id, "action": "INCIDENT_REJECTED"}).json() == []


def test_concurrent_simulations_cannot_both_win(iso_client):
    inc_id = _approved(iso_client)
    a, b = iso_client.session_factory(), iso_client.session_factory()
    try:
        stale = a.query(IncidentModel).filter(IncidentModel.id == inc_id).one()
        simulate_response(b, b.query(IncidentModel).filter(IncidentModel.id == inc_id).one(), "First")
        with pytest.raises(DecisionError):
            simulate_response(a, stale, "Second")
    finally:
        a.close()
        b.close()
    assert len(iso_client.get("/api/v1/audit-logs", params={"action": "RESPONSE_SIMULATED"}).json()) == 1


def test_audit_entries_never_contain_secrets_or_stack_traces(iso_client, monkeypatch):
    monkeypatch.setattr(settings, "LLM_API_KEY", "sk-should-never-appear")
    iso_client.post("/api/v1/alerts/seed")
    monkeypatch.setattr(EnrichmentAgent, "enrich_alert", lambda self, alert: (_ for _ in ()).throw(RuntimeError("down")))
    iso_client.post("/api/v1/pipeline/run")
    blob = json.dumps(iso_client.get("/api/v1/audit-logs", params={"limit": 200}).json())
    assert "sk-should-never-appear" not in blob and "Traceback" not in blob
