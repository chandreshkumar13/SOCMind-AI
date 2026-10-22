"""Phase 4 coverage that the per-agent test files do not include.

Uses the isolated `iso_client` fixture (own temporary database per test); nothing touches socmind.db.
"""
import json

from sqlalchemy import create_engine, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, sessionmaker

from app.agents.correlation.correlation_agent import CorrelationAgent
from app.agents.enrichment.enrichment_agent import EnrichmentAgent
from app.agents.investigation.investigation_agent import InvestigationAgent
from app.agents.response.response_agent import ResponseAgent
from app.agents.triage.triage_agent import TriageAgent
from app.db.session import ensure_columns
from app.models.base import Base
from app.models.models import IncidentModel
from app.services import orchestrator


def A(i, ts, **kw):
    return {"id": i, "timestamp": ts, "alert_title": f"alert {i}", "severity": "MEDIUM", **kw}


def _iocs(*pairs):
    """normalized_data carrying an enrichment result in the project's own contract."""
    return {"enrichment": {"iocs": [{"type": t, "value": v, "reputation": r, "provider": "MockThreatIntel", "confidence": 0.9,
                                     "source": "destination_ip", "evidence": "mock"} for t, v, r in pairs]}}


def _run_pipeline(client):
    client.post("/api/v1/alerts/seed")
    return client.post("/api/v1/pipeline/run").json()


def _finance_id(client):
    return next(i["id"] for i in client.get("/api/v1/incidents").json() if "ALT-2026-001" in i["correlated_alert_ids"])


# ------------------------------------------------------------------ correlation agent
def test_timestamps_with_different_offsets_are_compared_in_utc():
    # 00:00+05:30 is 18:30Z on the previous day: 15 minutes before the second alert, not 5.75 hours after it
    g = CorrelationAgent().correlate_alerts([A("a", "2026-09-03T00:00:00+05:30", host="H"), A("b", "2026-09-02T18:45:00Z", host="H")],
                                            window_hours=1)
    assert len(g) == 1 and g[0]["alert_ids"] == ["a", "b"]
    assert CorrelationAgent().correlate_alerts([A("a", "2026-09-03T00:00:00", host="H"), A("b", "2026-09-02T18:45:00Z", host="H")],
                                               window_hours=1) == []   # naive values are treated as UTC


def test_missing_and_malformed_timestamps_are_skipped_and_reported():
    agent = CorrelationAgent()
    groups = agent.correlate_alerts([A("a", "not-a-date", host="H"), A("b", None, host="H"), A("c", "", host="H"),
                                     A("d", "2026-09-03T08:00:00Z", host="H"), A("e", "2026-09-03T08:10:00Z", host="H")])
    assert [g["alert_ids"] for g in groups] == [["d", "e"]]
    assert sorted(agent.last_skipped["no_valid_timestamp"]) == ["a", "b", "c"]


def test_unknown_severity_missing_id_and_closed_alerts_do_not_crash_or_link():
    agent = CorrelationAgent()
    groups = agent.correlate_alerts([
        A("a", "2026-09-03T08:00:00Z", host="H", severity="bogus"), A("b", "2026-09-03T08:05:00Z", host="H", severity=None),
        {"timestamp": "2026-09-03T08:06:00Z", "host": "H"},                       # no id
        A("c", "2026-09-03T08:07:00Z", host="H", status="CLOSED")])
    assert len(groups) == 1 and groups[0]["alert_ids"] == ["a", "b"] and groups[0]["severity"] == "MEDIUM"
    assert agent.last_skipped["closed"] == ["c"] and agent.last_skipped["no_id"]


def test_ip_addresses_are_compared_in_canonical_form():
    g = CorrelationAgent().correlate_alerts([A("a", "2026-09-03T08:00:00Z", destination_ip="2001:DB8::1"),
                                             A("b", "2026-09-03T08:05:00Z", destination_ip="2001:db8:0:0:0:0:0:1")])
    assert len(g) == 1 and g[0]["reasons"]


def test_correlation_is_deterministic_and_keeps_unrelated_groups_apart():
    alerts = [A("a", "2026-09-03T08:00:00Z", host="H1"), A("b", "2026-09-03T08:05:00Z", host="H1"),
              A("c", "2026-09-03T08:00:00Z", host="H2"), A("d", "2026-09-03T08:05:00Z", host="H2", severity="HIGH")]
    first = CorrelationAgent().correlate_alerts(alerts)
    assert first == CorrelationAgent().correlate_alerts(list(reversed(alerts)))
    assert [g["alert_ids"] for g in first] == [["c", "d"], ["a", "b"]]       # HIGH group first, no cross-linking
    assert first[0]["confidence"] == "medium" and "share host" in first[0]["reasons"][0]


def test_two_shared_strong_entities_give_high_confidence():
    g = CorrelationAgent().correlate_alerts([A("a", "2026-09-03T08:00:00Z", host="H", file_hash="ab" * 16),
                                             A("b", "2026-09-03T08:05:00Z", host="h", file_hash="AB" * 16)])
    assert g[0]["confidence"] == "high" and len(g[0]["reasons"]) == 2


# ------------------------------------------------------------------ persistence, concurrency, migration
def test_correlation_retries_once_after_a_concurrent_insert_conflict(iso_client, monkeypatch):
    iso_client.post("/api/v1/alerts/seed")
    real_commit, calls = Session.commit, {"n": 0}

    def flaky(self):
        calls["n"] += 1
        if calls["n"] == 1:
            raise IntegrityError("INSERT", {}, Exception("UNIQUE constraint failed: incidents.id"))
        return real_commit(self)

    monkeypatch.setattr(Session, "commit", flaky)
    res = iso_client.post("/api/v1/incidents/correlate")
    assert res.status_code == 200 and len(res.json()["created"]) == 2
    monkeypatch.setattr(Session, "commit", real_commit)
    assert len(iso_client.get("/api/v1/incidents").json()) == 2          # no duplicates after the retry


def test_new_alert_keeps_the_incident_and_its_earlier_analysis(iso_client):
    _run_pipeline(iso_client)
    inc_id = _finance_id(iso_client)
    iso_client.post("/api/v1/alerts", json={"id": "ALT-LATE", "alert_title": "later", "host": "FINANCE-WKS-042", "timestamp": "2026-09-03T09:00:00Z"})
    res = iso_client.post("/api/v1/incidents/correlate").json()
    assert res["updated"] == [inc_id] and res["created"] == []
    inc = iso_client.get(f"/api/v1/incidents/{inc_id}").json()
    assert "ALT-LATE" in inc["correlated_alert_ids"] and len(iso_client.get("/api/v1/incidents").json()) == 2
    assert inc["details"]["investigation"] and inc["details"]["investigation_stale"] is True       # kept, but marked out of date
    assert inc["details"]["recommendations"] and inc["details"]["recommendations_stale"] is True


def test_old_database_rows_survive_the_in_place_upgrade(tmp_path):
    engine = create_engine(f"sqlite:///{tmp_path / 'old.db'}")
    Base.metadata.create_all(bind=engine)
    with engine.begin() as c:                       # recreate the incidents table as it was before the details column
        c.execute(text("DROP TABLE incidents"))
        c.execute(text("CREATE TABLE incidents (id VARCHAR PRIMARY KEY, created_at DATETIME, title VARCHAR, severity VARCHAR, status VARCHAR, "
                       "correlated_alert_ids JSON, ai_summary TEXT, recommended_action VARCHAR, human_approval_status VARCHAR)"))
        c.execute(text("INSERT INTO incidents (id, title, severity, status, correlated_alert_ids, human_approval_status) "
                       "VALUES ('INC-OLD-001', 'Old incident', 'HIGH', 'OPEN', '[\"A1\", \"A2\"]', 'APPROVED')"))
    ensure_columns(engine)
    with sessionmaker(bind=engine)() as db:
        inc = db.query(IncidentModel).filter(IncidentModel.id == "INC-OLD-001").one()
        assert (inc.title, inc.severity, inc.human_approval_status, inc.correlated_alert_ids) == ("Old incident", "HIGH", "APPROVED", ["A1", "A2"])
        assert inc.details is None
        inc.details = {"note": "added after upgrade"}
        db.commit()
    with sessionmaker(bind=engine)() as db:
        assert db.query(IncidentModel).one().details == {"note": "added after upgrade"}


def test_incident_without_details_is_served_by_the_api(iso_client):
    db = iso_client.session_factory()
    db.add(IncidentModel(id="INC-OLD-002", title="Legacy", severity="LOW", status="OPEN", correlated_alert_ids=[], human_approval_status="PENDING"))
    db.commit()
    db.close()
    body = iso_client.get("/api/v1/incidents/INC-OLD-002").json()
    assert body["details"] is None and body["alerts"] == []
    assert iso_client.post("/api/v1/incidents/INC-OLD-002/approve", json={"reviewer": "A"}).status_code == 409   # nothing to review


def test_unknown_incident_and_bad_window_responses(iso_client):
    for path in ("investigate", "recommend", "approve", "reject"):
        body = {"reviewer": "A"} if path in ("approve", "reject") else None
        assert iso_client.post(f"/api/v1/incidents/NOPE/{path}", json=body).status_code == 404
    assert iso_client.post("/api/v1/incidents/correlate", json={"window_hours": 169}).status_code == 422
    assert iso_client.post("/api/v1/incidents/correlate", json={"window_hours": "x"}).status_code == 422


# ------------------------------------------------------------------ investigation
def test_investigation_uses_triage_correlation_and_the_enrichment_contract(iso_client):
    _run_pipeline(iso_client)
    inv = iso_client.get(f"/api/v1/incidents/{_finance_id(iso_client)}").json()["details"]["investigation"]
    assert inv["triage"]["max_suspicion_score"] > 0 and inv["triage"]["alerts_triaged"] == 3
    statements = [f["statement"] for f in inv["findings"] if f["type"] == "verified"]
    assert any(s.startswith("Correlation evidence:") for s in statements) and any("Deterministic triage rated" in s for s in statements)
    intel = [f for f in inv["findings"] if f["type"] == "mock_intel"]
    assert intel and all(f["reputation"] in ("MALICIOUS", "SUSPICIOUS") and "Unverified" in f["statement"] for f in intel)
    assert any("185.220.101.5" in f["statement"] for f in intel)
    assert "185.220.101.5" in inv["entities"]["ips"] and len(inv["entities"]["hashes"]) >= 1 and inv["entities"]["users"] == ["j.doe"]
    assert inv["counts"]["hypothesis"] == len([f for f in inv["findings"] if f["type"] == "hypothesis"])


def test_investigation_states_missing_data_instead_of_inventing_it():
    inv = InvestigationAgent().investigate({"id": "I"}, [A("a", None, host="H"), A("b", "garbage", host="H")], [])
    assert [e["time"] for e in inv["timeline"]] == [None, None]                   # unknown times are not made up
    assert inv["time_span"]["first"] is None
    text_ = " ".join(inv["limitations"])
    assert "no valid timestamp" in text_ and "no triage result" in text_ and "no enrichment result" in text_
    assert not any(f["type"] == "mock_intel" for f in inv["findings"])
    empty = InvestigationAgent().investigate({"id": "I"}, [], [])
    assert empty["evidence_strength"] == "weak" and "no readable alerts" in " ".join(empty["limitations"])


def test_clean_and_unknown_reputations_are_never_reported_as_threats():
    alerts = [A("a", "2026-09-03T08:00:00Z", host="H", normalized_data=_iocs(("IP", "10.0.0.1", "CLEAN"), ("IP", "8.8.8.8", "UNKNOWN"))),
              A("b", "2026-09-03T08:05:00Z", host="H")]
    inv = InvestigationAgent().investigate({"id": "I"}, alerts, [])
    assert not any(f["type"] == "mock_intel" for f in inv["findings"])
    assert any("not verified" in lim for lim in inv["limitations"])


def test_timeline_times_share_one_utc_format_and_are_ordered():
    alerts = [A("late", "2026-09-03T05:30:00+05:30", host="H"), A("early", "2026-09-02T23:30:00Z", host="H")]   # both are before 2026-09-03T00:00Z
    inv = InvestigationAgent().investigate({"id": "I"}, alerts, [])
    assert [e["ref"] for e in inv["timeline"]] == ["early", "late"]
    assert all(e["time"].endswith("Z") for e in inv["timeline"])


# ------------------------------------------------------------------ response
REQUIRED_REC_FIELDS = ("id", "category", "priority", "action", "target", "justification", "supporting_evidence", "expected_benefit", "impact",
                       "operational_impact", "risk_if_wrong", "reversible", "rollback", "required_approvals", "preconditions",
                       "validation_steps", "requires_approval", "status", "executed")


def test_every_recommendation_is_complete_and_never_executed(iso_client):
    _run_pipeline(iso_client)
    for inc in iso_client.get("/api/v1/incidents").json():
        recs = inc["details"]["recommendations"]
        assert recs
        for r in recs:
            assert all(k in r for k in REQUIRED_REC_FIELDS)
            assert r["expected_benefit"] and r["operational_impact"] and r["risk_if_wrong"] and r["rollback"]
            assert r["required_approvals"] and r["preconditions"] and r["validation_steps"]
            assert r["requires_approval"] is True and r["executed"] is False and r["status"] == "PENDING"
        assert inc["details"]["response"]["execution_mode"] == "simulation_only"
        assert inc["human_approval_status"] == "PENDING"


def test_finance_incident_covers_blocking_persistence_hash_and_evidence_preservation(iso_client):
    _run_pipeline(iso_client)
    recs = iso_client.get(f"/api/v1/incidents/{_finance_id(iso_client)}").json()["details"]["recommendations"]
    assert {"ioc_blocking", "persistence_removal", "evidence_preservation"} <= {r["category"] for r in recs}
    block = next(r for r in recs if r["action"].startswith("Block outbound traffic"))
    assert any("mock" in p.lower() for p in block["preconditions"]) and "mock" in block["justification"].lower()
    assert [r["priority"] for r in recs] == sorted(r["priority"] for r in recs)
    assert [r["id"] for r in recs] == [f"REC-{n}" for n in range(1, len(recs) + 1)]


def test_blocking_is_driven_by_malicious_reputation_in_the_project_contract():
    inc = {"id": "I", "severity": "HIGH"}
    base = [A("a", "2026-09-03T08:00:00Z", host="H", destination_ip="9.9.9.9", alert_title="Outbound connection"),
            A("b", "2026-09-03T08:05:00Z", host="H", destination_ip="9.9.9.9", alert_title="Another")]
    flagged = [dict(a, normalized_data=_iocs(("IP", "9.9.9.9", "MALICIOUS"))) for a in base]
    clean = [dict(a, normalized_data=_iocs(("IP", "9.9.9.9", "CLEAN"))) for a in base]
    actions = lambda alerts: [r["action"] for r in ResponseAgent().recommend(inc, alerts, {"evidence_strength": "moderate"})["recommendations"]]
    assert any(a.startswith("Block outbound traffic to 9.9.9.9") for a in actions(flagged))
    assert not any(a.startswith("Block outbound") for a in actions(clean))
    assert not any(a.startswith("Block outbound") for a in actions(base))          # no enrichment, no blocking proposal


def test_weak_evidence_gets_an_investigation_recommendation_only():
    out = ResponseAgent().recommend({"id": "I", "severity": "CRITICAL"}, [A("a", "2026-09-03T08:00:00Z", host="H", alert_title="ransomware encryptor")], None)
    (rec,) = out["recommendations"]
    assert rec["category"] == "investigation" and rec["impact"] == "NONE" and out["max_impact"] == "NONE"


def test_approval_is_only_a_recorded_decision(iso_client):
    _run_pipeline(iso_client)
    inc_id = _finance_id(iso_client)
    body = iso_client.post(f"/api/v1/incidents/{inc_id}/approve", json={"reviewer": "Chandresh", "reason": "ok"}).json()
    assert body["status"] == "RESPONSE_APPROVED" and "no action was executed" in body["details"]["review"]["execution"]
    assert all(r["executed"] is False for r in body["details"]["recommendations"])
    assert iso_client.post("/api/v1/pipeline/run").json()["stages"][-1]["processed"] == 0       # decided incidents are not re-recommended


# ------------------------------------------------------------------ orchestration
def test_alerts_move_through_the_documented_statuses(iso_client):
    _run_pipeline(iso_client)
    status = {a["id"]: a["status"] for a in iso_client.get("/api/v1/alerts", params={"limit": 100}).json()}
    assert status["ALT-2026-001"] == status["ALT-2026-006"] == "INVESTIGATING"        # in an incident
    assert status["ALT-2026-002"] == "ENRICHED"                                      # analysed but not correlated
    assert "CLOSED" not in status.values()


def test_stored_enrichment_keeps_the_original_contract_after_a_pipeline_run(iso_client):
    _run_pipeline(iso_client)
    enr = iso_client.get("/api/v1/alerts/ALT-2026-001").json()["normalized_data"]["enrichment"]
    assert {"total_iocs_extracted", "summary", "iocs", "agent", "status", "alert_id"} <= set(enr)
    assert "results" not in enr and enr["total_iocs_extracted"] == len(enr["iocs"])
    assert {i["type"] for i in enr["iocs"]} <= {"IP", "SHA256", "SHA1", "MD5", "DOMAIN", "URL"}
    assert enr["verified"] is False and enr["intel_mode"] == "mock"


def test_pipeline_reports_unknown_and_closed_ids(iso_client):
    iso_client.post("/api/v1/alerts/seed")
    iso_client.delete("/api/v1/alerts/ALT-2026-002")
    assert iso_client.post("/api/v1/pipeline/run", json={"alert_ids": ["NOPE-1", "NOPE-2"]}).status_code == 404
    run = iso_client.post("/api/v1/pipeline/run", json={"alert_ids": ["ALT-2026-001", "ALT-2026-002", "NOPE"]}).json()
    assert run["alerts_in_scope"] == 1 and run["unknown_alert_ids"] == ["NOPE"] and run["closed_alert_ids"] == ["ALT-2026-002"]
    assert any("NOPE" in w for w in run["warnings"]) and any("ALT-2026-002" in w for w in run["warnings"])
    assert iso_client.get("/api/v1/alerts/ALT-2026-002").json()["status"] == "CLOSED"


def test_pipeline_outcome_is_success_partial_or_failure(iso_client, monkeypatch):
    iso_client.post("/api/v1/alerts/seed")
    ok = iso_client.post("/api/v1/pipeline/run").json()
    assert ok["outcome"] == "success" and ok["status"] == "completed" and ok["warnings"] == []

    def boom(*a, **k):
        raise RuntimeError("down")
    iso_client.post("/api/v1/alerts", json={"id": "ALT-N", "alert_title": "n", "host": "X"})
    monkeypatch.setattr(EnrichmentAgent, "enrich_alert", boom)
    partial = iso_client.post("/api/v1/pipeline/run").json()
    assert partial["outcome"] == "partial" and partial["status"] == "completed_with_errors"
    assert any("without that intelligence" in w for w in partial["warnings"])

    monkeypatch.setattr(TriageAgent, "analyze_alert", boom)
    monkeypatch.setattr(CorrelationAgent, "correlate_alerts", boom)
    iso_client.post("/api/v1/alerts", json={"id": "ALT-M", "alert_title": "m", "host": "Y"})
    failed = iso_client.post("/api/v1/pipeline/run").json()
    assert failed["outcome"] == "failure" and failed["status"] == "failed"


def test_stage_errors_are_short_and_have_no_stack_trace(iso_client, monkeypatch):
    iso_client.post("/api/v1/alerts/seed")
    monkeypatch.setattr(EnrichmentAgent, "enrich_alert", lambda self, alert: (_ for _ in ()).throw(RuntimeError("x" * 2000)))
    run = iso_client.post("/api/v1/pipeline/run").json()
    errors = next(s for s in run["stages"] if s["agent"] == "Enrichment Agent")["errors"]
    assert errors and all(len(e) < 400 and "Traceback" not in e for e in errors)


def test_a_second_concurrent_run_is_refused(iso_client):
    iso_client.post("/api/v1/alerts/seed")
    assert orchestrator._RUN_LOCK.acquire(blocking=False)
    try:
        res = iso_client.post("/api/v1/pipeline/run")
    finally:
        orchestrator._RUN_LOCK.release()
    assert res.status_code == 409 and "already in progress" in res.json()["detail"]
    assert iso_client.post("/api/v1/pipeline/run").status_code == 200           # the lock is released again


def test_pipeline_leaves_an_audit_trail_for_every_stage(iso_client):
    run = _run_pipeline(iso_client)
    actions = {l["action"] for l in iso_client.get("/api/v1/audit-logs", params={"limit": 200}).json()}
    assert {"ALERT_TRIAGED", "ALERT_ENRICHED", "INCIDENT_CREATED", "INCIDENT_INVESTIGATED", "RESPONSE_RECOMMENDED", "PIPELINE_RUN"} <= actions
    stored = iso_client.get("/api/v1/audit-logs", params={"action": "PIPELINE_RUN"}).json()[0]["details"]
    assert stored["run_id"] == run["run_id"] and stored["outcome"] == "success"


def test_no_placeholder_values_leak_into_results(iso_client):
    _run_pipeline(iso_client)
    blob = json.dumps(iso_client.get("/api/v1/incidents").json())
    assert "INC-CANDIDATE" not in blob and "placeholder" not in blob.lower()
