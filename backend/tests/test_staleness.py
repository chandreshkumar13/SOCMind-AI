"""Stale incident analysis: which enrichment changes count, how stale analysis is marked, how it is refreshed, and how
recorded decisions are withdrawn. Live lookups use a fake VirusTotal on an httpx MockTransport: no network.
"""
import copy
import json

import httpx
import pytest
from pydantic import SecretStr

from app.core.config import settings
from app.models.models import AlertModel, IncidentModel
from app.services import threat_intel
from app.services.staleness import describe_enrichment_change, enrichment_fingerprint
from app.tools.virustotal import VirusTotalClient
from vt_helpers import KEY, Clock, Server, flags_bad_ip


# ------------------------------------------------------------------ helpers
def _seed_and_run(client):
    client.post("/api/v1/alerts/seed")
    return client.post("/api/v1/pipeline/run").json()


def _finance(client):
    return next(i["id"] for i in client.get("/api/v1/incidents").json() if "ALT-2026-001" in i["correlated_alert_ids"])


def _details(client, inc_id):
    return client.get(f"/api/v1/incidents/{inc_id}").json()["details"]


def _audit(client, action, target=None):
    params = {"action": action, **({"target_id": target} if target else {})}
    return client.get("/api/v1/audit-logs", params=params).json()


def _late_alert(client, alert_id="LATE-A"):
    """A new alert on the finance host that is ingested and correlated but NOT enriched. Its domain is flagged by the
    mock intelligence and appears nowhere else, so its contribution to the findings is visible."""
    res = client.post("/api/v1/alerts", json={"id": alert_id, "alert_title": "late", "host": "FINANCE-WKS-042",
                                              "timestamp": "2026-09-03T09:10:00Z", "destination_ip": "185.220.101.5",
                                              "description": "Beaconing to malicious-domain.net"})
    assert res.status_code == 201
    client.post("/api/v1/incidents/correlate")


@pytest.fixture
def live(monkeypatch):
    """Switches enrichment to VirusTotal on a fake server. Returns the fake server (its .requests lists every call)."""
    def switch(respond=None, **overrides):
        server, clock = Server(respond or flags_bad_ip), Clock()
        monkeypatch.setattr(settings, "THREAT_INTEL_PROVIDER", "virustotal")
        monkeypatch.setattr(settings, "VIRUSTOTAL_API_KEY", SecretStr(KEY))
        monkeypatch.setattr(settings, "VIRUSTOTAL_REQUESTS_PER_MINUTE", 1000)
        for name, value in overrides.items():
            monkeypatch.setattr(settings, name, value)
        real = VirusTotalClient
        monkeypatch.setattr(threat_intel, "VirusTotalClient",
                            lambda *a, **k: real(*a, transport=httpx.MockTransport(server), clock=clock, **k))
        threat_intel.reset_client()
        return server
    return switch


def _mock_result(**over):
    base = {"intel_mode": "mock", "verified": False, "timestamp": "2026-10-26T09:00:00+00:00", "iocs": [
        {"type": "IP", "value": "185.220.101.5", "reputation": "MALICIOUS", "confidence": 0.95, "evidence": "Known C2 server.",
         "provider": "MockThreatIntel", "source": "destination_ip"},
        {"type": "IP", "value": "10.0.0.5", "reputation": "CLEAN", "confidence": 1.0, "evidence": "Internal address.",
         "provider": "local-policy", "source": "source_ip"}]}
    base.update(over)
    return base


def _live_result(**over):
    base = {"intel_mode": "live", "provider": "VirusTotal", "incomplete": False, "timestamp": "2026-10-26T09:00:00+00:00",
            "lookup_summary": {"requests_made": 1, "from_cache": 0}, "iocs": [
                {"type": "IP", "value": "185.220.101.5", "reputation": "MALICIOUS", "confidence": 0.17,
                 "evidence": "12 of 70 engines flagged it as malicious (VirusTotal, analysed 2026-10-24).", "provider": "VirusTotal",
                 "retrieved_at": "2026-10-26T09:00:00Z", "cached": False, "lookup_status": "completed"}]}
    base.update(over)
    return base


# ------------------------------------------------------------------ the rule: what is and is not material
def test_retrieval_timing_and_cache_hits_are_not_a_change():
    before = _live_result()
    after = copy.deepcopy(before)
    after["iocs"][0].update(retrieved_at="2026-10-27T10:00:00Z", cached=True)
    after.update(timestamp="2026-10-27T10:00:00+00:00", lookup_summary={"requests_made": 0, "from_cache": 1})
    assert describe_enrichment_change(before, after) is None


def test_a_re_run_of_the_same_mock_enrichment_is_not_a_change():
    assert describe_enrichment_change(_mock_result(), _mock_result(timestamp="2030-01-01T00:00:00+00:00")) is None


def test_the_first_enrichment_is_a_change():
    assert describe_enrichment_change(None, _mock_result()) == "enrichment recorded for the first time"


def test_mock_to_live_is_described_as_a_source_change():
    assert describe_enrichment_change(_mock_result(), _live_result()) == "threat-intelligence source changed: mock -> live (VirusTotal)"


def test_live_to_mock_is_also_a_source_change():
    assert describe_enrichment_change(_live_result(), _mock_result()) == "threat-intelligence source changed: live (VirusTotal) -> mock"


def test_a_flagged_verdict_or_its_evidence_changing_is_a_change():
    changed = _live_result()
    changed["iocs"][0]["evidence"] = "13 of 70 engines flagged it as malicious (VirusTotal, analysed 2026-10-27)."
    assert describe_enrichment_change(_live_result(), changed) == "reputation or evidence of a flagged indicator changed"
    downgraded = _live_result()
    downgraded["iocs"][0]["reputation"] = "SUSPICIOUS"
    assert describe_enrichment_change(_live_result(), downgraded) == "reputation or evidence of a flagged indicator changed"


def test_clean_versus_unknown_on_an_unflagged_indicator_is_not_material():
    """The analysis never quotes unflagged reputations, so flipping them does not change any finding or recommendation."""
    other = _mock_result()
    other["iocs"][1]["reputation"] = "UNKNOWN"
    assert describe_enrichment_change(_mock_result(), other) is None


def test_lookups_completing_or_becoming_incomplete_are_changes():
    assert describe_enrichment_change(_live_result(incomplete=True), _live_result(incomplete=False)) == "lookups completed"
    assert describe_enrichment_change(_live_result(), _live_result(incomplete=True)) == "lookups became incomplete"


def test_an_indicator_added_or_removed_is_a_change():
    more = _mock_result()
    more["iocs"].append({"type": "DOMAIN", "value": "evil-domain.com", "reputation": "UNKNOWN", "confidence": 0.0,
                         "evidence": "x", "provider": "MockDomainIntel"})
    assert describe_enrichment_change(_mock_result(), more) == "extracted indicators changed"


def test_fingerprint_tolerates_malformed_results():
    assert enrichment_fingerprint(None) is None and enrichment_fingerprint("garbage") is None
    messy = {"intel_mode": "live", "provider": "VirusTotal", "iocs": [None, {"type": "IP", "value": "8.8.8.8", "reputation": "MALICIOUS"}]}
    assert enrichment_fingerprint(messy)["indicators"] == [["IP", "8.8.8.8"]]


# ------------------------------------------------------------------ marking
def test_identical_mock_re_enrichment_leaves_the_incident_fresh(iso_client):
    _seed_and_run(iso_client)
    inc = _finance(iso_client)
    before = _details(iso_client, inc)
    assert before["investigation_stale"] is False and before["recommendations_stale"] is False
    assert iso_client.post("/api/v1/alerts/ALT-2026-001/enrich").status_code == 200
    after = _details(iso_client, inc)
    assert after["investigation_stale"] is False and after["recommendations_stale"] is False
    assert not after.get("stale_reasons") and after["recommendations"] == before["recommendations"]
    assert _audit(iso_client, "INCIDENT_STALE", inc) == []
    latest = _audit(iso_client, "ALERT_ENRICHED", "ALT-2026-001")[0]["details"]
    assert latest["material_change"] is False and latest["incidents_marked_stale"] == []


def test_enrichment_arriving_after_the_investigation_marks_the_incident_stale(iso_client):
    _seed_and_run(iso_client)
    inc = _finance(iso_client)
    _late_alert(iso_client)
    iso_client.post(f"/api/v1/incidents/{inc}/investigate")          # the investigation runs with LATE-A unenriched
    assert _details(iso_client, inc)["investigation_stale"] is False
    assert iso_client.post("/api/v1/alerts/LATE-A/enrich").status_code == 200
    after = _details(iso_client, inc)
    assert after["investigation_stale"] is True and after["recommendations_stale"] is True
    assert after["stale_reasons"] == [{"alert_id": "LATE-A", "change": "enrichment recorded for the first time",
                                       "at": after["stale_reasons"][0]["at"]}]
    (mark,) = _audit(iso_client, "INCIDENT_STALE", inc)
    assert mark["actor"] == "Enrichment Agent" and mark["target_id"] == inc
    assert mark["details"] == {"alert_id": "LATE-A", "change": "enrichment recorded for the first time", "decision_withdrawn": False}
    latest = _audit(iso_client, "ALERT_ENRICHED", "LATE-A")[0]["details"]
    assert latest["material_change"] is True and latest["incidents_marked_stale"] == [inc]


def test_an_incident_with_no_analysis_yet_is_not_marked(iso_client):
    iso_client.post("/api/v1/alerts/seed")
    iso_client.post("/api/v1/incidents/correlate")                    # grouped, but never investigated
    inc = _finance(iso_client)
    before = _details(iso_client, inc)
    assert "investigation" not in before and "recommendations" not in before
    iso_client.post("/api/v1/alerts/ALT-2026-001/enrich")
    after = _details(iso_client, inc)
    assert "stale_reasons" not in after and _audit(iso_client, "INCIDENT_STALE", inc) == []


def test_merged_incidents_are_left_alone(iso_client, live):
    _seed_and_run(iso_client)
    inc = _finance(iso_client)
    db = iso_client.session_factory()
    db.query(IncidentModel).filter(IncidentModel.id == inc).one().status = "MERGED"
    db.commit()
    db.close()
    live()
    iso_client.post("/api/v1/alerts/ALT-2026-001/enrich")
    after = _details(iso_client, inc)
    assert after["investigation_stale"] is False and not after.get("stale_reasons")


def test_repeated_material_changes_are_each_recorded_with_a_bounded_history(iso_client, monkeypatch):
    _seed_and_run(iso_client)
    inc = _finance(iso_client)
    for i in range(22):                                              # alternate mock <-> unavailable: a real change each time
        monkeypatch.setattr(settings, "THREAT_INTEL_MOCK_MODE", i % 2 == 1)
        assert iso_client.post("/api/v1/alerts/ALT-2026-001/enrich").status_code == 200
    details = _details(iso_client, inc)
    assert len(details["stale_reasons"]) == 20                       # bounded
    assert len(_audit(iso_client, "INCIDENT_STALE", inc)) == 22      # every change is in the audit trail


# ------------------------------------------------------------------ re-investigation and the pipeline
def test_reinvestigation_refreshes_the_findings_but_not_the_recommendations(iso_client):
    _seed_and_run(iso_client)
    inc = _finance(iso_client)
    _late_alert(iso_client)
    iso_client.post(f"/api/v1/incidents/{inc}/investigate")
    iso_client.post("/api/v1/alerts/LATE-A/enrich")
    iso_client.post(f"/api/v1/incidents/{inc}/investigate")
    details = _details(iso_client, inc)
    assert details["investigation_stale"] is False
    assert details["recommendations_stale"] is True and details["stale_reasons"]   # not regenerated yet
    assert any(f["type"] == "mock_intel" and "malicious-domain.net" in f["statement"] for f in details["investigation"]["findings"])
    assert not any("no enrichment result" in lim for lim in details["investigation"]["limitations"])


def test_the_pipeline_refreshes_stale_analysis_from_the_latest_enrichment(iso_client):
    _seed_and_run(iso_client)
    inc = _finance(iso_client)
    _late_alert(iso_client)
    iso_client.post(f"/api/v1/incidents/{inc}/investigate")
    iso_client.post("/api/v1/alerts/LATE-A/enrich")
    run = iso_client.post("/api/v1/pipeline/run").json()
    stages = {s["agent"]: s for s in run["stages"]}
    assert stages["Investigation Agent"]["processed"] >= 1 and stages["Response Agent"]["processed"] >= 1
    details = _details(iso_client, inc)
    assert details["investigation_stale"] is False and details["recommendations_stale"] is False
    assert details["stale_reasons"] == []
    assert any(f["type"] == "mock_intel" and "malicious-domain.net" in f["statement"] for f in details["investigation"]["findings"])
    assert any(e["ref"] == "LATE-A" for e in details["investigation"]["timeline"])
    assert details["recommendations"] and all(r["executed"] is False for r in details["recommendations"])


def test_a_second_pipeline_run_after_refresh_does_no_analysis_work(iso_client):
    _seed_and_run(iso_client)
    inc = _finance(iso_client)
    _late_alert(iso_client)
    iso_client.post("/api/v1/alerts/LATE-A/enrich")
    iso_client.post("/api/v1/pipeline/run")
    again = iso_client.post("/api/v1/pipeline/run").json()
    assert all(s["processed"] == 0 for s in again["stages"])
    assert _details(iso_client, inc)["investigation_stale"] is False


# ------------------------------------------------------------------ mock -> live, and unchanged live results
def test_mock_to_live_transition_marks_the_analysis_stale_and_the_refresh_reports_live_findings(iso_client, live):
    _seed_and_run(iso_client)
    inc = _finance(iso_client)
    before = _details(iso_client, inc)["investigation"]["findings"]
    assert any(f["type"] == "mock_intel" and "alert:ALT-2026-001" in f["basis"] for f in before)
    secret_free = live()
    iso_client.post("/api/v1/alerts/ALT-2026-001/enrich")
    marked = _details(iso_client, inc)
    assert marked["investigation_stale"] is True
    assert marked["stale_reasons"][-1]["change"] == "threat-intelligence source changed: mock -> live (VirusTotal)"
    run = iso_client.post("/api/v1/pipeline/run").json()
    assert run["outcome"] == "success"
    refreshed = _details(iso_client, inc)
    assert refreshed["investigation_stale"] is False and refreshed["recommendations_stale"] is False
    findings = refreshed["investigation"]["findings"]
    assert any(f["type"] == "external_intel" and "185.220.101.5" in f["statement"] and "alert:ALT-2026-001" in f["basis"] for f in findings)
    assert not any(f["type"] == "mock_intel" and "alert:ALT-2026-001" in f["basis"] for f in findings)
    assert refreshed["investigation"]["counts"]["external_intel"] >= 1
    assert secret_free.requests                                       # the live path really ran, against the fake server
    blob = json.dumps(_audit(iso_client, "INCIDENT_STALE", inc)) + json.dumps(refreshed)
    assert KEY not in blob and "x-apikey" not in blob.lower()


def test_repeating_live_enrichment_with_the_same_verdicts_is_a_no_op(iso_client, live):
    server = live()
    _seed_and_run(iso_client)
    inc = _finance(iso_client)
    before = _details(iso_client, inc)
    requests_before = len(server.requests)
    res = iso_client.post("/api/v1/alerts/ALT-2026-001/enrich").json()["enrichment_result"]
    assert res["lookup_summary"]["requests_made"] == 0 and len(server.requests) == requests_before     # served from cache
    after = _details(iso_client, inc)
    assert after["investigation_stale"] is False and after["recommendations_stale"] is False
    assert after["recommendations"] == before["recommendations"]
    assert _audit(iso_client, "INCIDENT_STALE", inc) == []
    assert _audit(iso_client, "ALERT_ENRICHED", "ALT-2026-001")[0]["details"]["material_change"] is False


# ------------------------------------------------------------------ human decisions are safeguarded
def test_a_recorded_decision_is_withdrawn_when_its_enrichment_changes(iso_client, live):
    _seed_and_run(iso_client)
    inc = _finance(iso_client)
    assert iso_client.post(f"/api/v1/incidents/{inc}/approve", json={"reviewer": "Analyst A", "reason": "ok"}).status_code == 200
    assert iso_client.post(f"/api/v1/incidents/{inc}/simulate", json={"reviewer": "Analyst B"}).status_code == 200
    live()
    iso_client.post("/api/v1/alerts/ALT-2026-001/enrich")

    body = iso_client.get(f"/api/v1/incidents/{inc}").json()
    assert body["human_approval_status"] == "PENDING" and body["status"] == "OPEN"
    assert "review" not in body["details"] and "simulation" not in body["details"]
    (old,) = body["details"]["review_history"]
    assert old["review"]["decision"] == "APPROVED" and old["review"]["reviewer"] == "Analyst A"
    assert old["simulation"]["simulated_by"] == "Analyst B"
    assert "threat intelligence for alert ALT-2026-001 changed" in old["superseded_by"]
    (reset,) = _audit(iso_client, "APPROVAL_RESET", inc)
    assert reset["actor"] == "Enrichment Agent"
    assert reset["details"]["previous"] == "APPROVED" and "threat intelligence" in reset["details"]["reason"]

    stale = iso_client.post(f"/api/v1/incidents/{inc}/approve", json={"reviewer": "Analyst A"})
    assert stale.status_code == 409 and "out of date" in stale.json()["detail"]
    assert iso_client.post(f"/api/v1/incidents/{inc}/simulate", json={"reviewer": "Analyst A"}).status_code == 409

    run = iso_client.post("/api/v1/pipeline/run").json()
    assert {s["agent"]: s for s in run["stages"]}["Response Agent"]["processed"] >= 1
    regenerated = iso_client.get(f"/api/v1/incidents/{inc}").json()
    assert regenerated["details"]["recommendations_stale"] is False and regenerated["human_approval_status"] == "PENDING"
    assert all(r["executed"] is False and r["status"] == "PENDING" for r in regenerated["details"]["recommendations"])

    approved = iso_client.post(f"/api/v1/incidents/{inc}/approve", json={"reviewer": "Analyst C"})
    assert approved.status_code == 200 and approved.json()["status"] == "RESPONSE_APPROVED"
    assert approved.json()["details"]["review"]["reviewer"] == "Analyst C"


def test_a_rejected_decision_is_withdrawn_too(iso_client, live):
    _seed_and_run(iso_client)
    inc = _finance(iso_client)
    iso_client.post(f"/api/v1/incidents/{inc}/reject", json={"reviewer": "Analyst A"})
    live()
    iso_client.post("/api/v1/alerts/ALT-2026-001/enrich")
    body = iso_client.get(f"/api/v1/incidents/{inc}").json()
    assert body["human_approval_status"] == "PENDING"
    assert body["details"]["review_history"][0]["review"]["decision"] == "REJECTED"


def test_no_response_is_executed_by_any_of_this(iso_client, live):
    _seed_and_run(iso_client)
    inc = _finance(iso_client)
    iso_client.post(f"/api/v1/incidents/{inc}/approve", json={"reviewer": "Analyst A"})
    live()
    iso_client.post("/api/v1/alerts/ALT-2026-001/enrich")
    iso_client.post("/api/v1/pipeline/run")
    text = json.dumps(iso_client.get(f"/api/v1/incidents/{inc}").json())
    assert "EXECUTED" not in text and '"executed": true' not in text
    assert iso_client.get("/api/v1/config").json()["execution_mode"] == "simulation_only"


# ------------------------------------------------------------------ the existing correlation path still behaves the same
def test_correlation_still_withdraws_a_decision_with_its_own_reason(iso_client):
    _seed_and_run(iso_client)
    inc = _finance(iso_client)
    iso_client.post(f"/api/v1/incidents/{inc}/approve", json={"reviewer": "Analyst A"})
    iso_client.post("/api/v1/alerts", json={"id": "CORR-NEW", "alert_title": "corr", "host": "FINANCE-WKS-042", "timestamp": "2026-09-03T09:20:00Z"})
    iso_client.post("/api/v1/incidents/correlate")
    body = iso_client.get(f"/api/v1/incidents/{inc}").json()
    assert body["human_approval_status"] == "PENDING"
    assert body["details"]["review_history"][0]["superseded_by"] == "new correlated alerts changed the incident after a decision"
    (reset,) = _audit(iso_client, "APPROVAL_RESET", inc)
    assert reset["details"]["reason"] == "new correlated alerts changed the incident after a decision"


# ------------------------------------------------------------------ reconciliation before each pipeline run
def _edit_incident_details(client, inc_id, change):
    db = client.session_factory()
    try:
        row = db.query(IncidentModel).filter(IncidentModel.id == inc_id).one()
        details = copy.deepcopy(row.details or {})
        change(details)
        row.details = details
        db.commit()
    finally:
        db.close()


def _edit_alert_enrichment(client, alert_id, change):
    """Changes an alert's stored enrichment directly, the way data written before change tracking could be."""
    db = client.session_factory()
    try:
        row = db.query(AlertModel).filter(AlertModel.id == alert_id).one()
        data = copy.deepcopy(row.normalized_data or {})
        change(data["enrichment"])
        row.normalized_data = data
        db.commit()
    finally:
        db.close()


def test_investigation_records_the_evidence_it_was_built_from(iso_client):
    _seed_and_run(iso_client)
    inc = _finance(iso_client)
    basis = _details(iso_client, inc)["analysis_basis"]
    alerts = iso_client.get(f"/api/v1/incidents/{inc}").json()["alerts"]
    assert sorted(basis) == sorted(a["id"] for a in alerts)
    assert all(isinstance(v, str) and len(v) == 64 for v in basis.values())     # enriched alerts: a sha256 digest


def test_pipeline_refreshes_analysis_built_before_change_tracking(iso_client):
    _seed_and_run(iso_client)
    inc = _finance(iso_client)
    _edit_incident_details(iso_client, inc, lambda d: d.pop("analysis_basis", None))      # what older data looks like
    run = iso_client.post("/api/v1/pipeline/run").json()
    assert {s["agent"]: s for s in run["stages"]}["Investigation Agent"]["processed"] >= 1
    marks = _audit(iso_client, "INCIDENT_STALE", inc)
    assert len(marks) == 1 and marks[0]["details"]["alert_id"] is None
    assert "before change tracking" in marks[0]["details"]["change"]
    details = _details(iso_client, inc)
    assert details["analysis_basis"] and details["investigation_stale"] is False and details["recommendations_stale"] is False
    assert details["stale_reasons"] == []


def test_pipeline_catches_evidence_that_changed_without_being_marked(iso_client):
    _seed_and_run(iso_client)
    inc = _finance(iso_client)

    def add_flagged_domain(enr):
        enr["iocs"].append({"type": "DOMAIN", "value": "malicious-domain.net", "reputation": "MALICIOUS", "confidence": 0.9,
                            "evidence": "Known malware distribution domain.", "provider": "MockDomainIntel", "source": "description"})
        enr["total_iocs_extracted"] = len(enr["iocs"])
    _edit_alert_enrichment(iso_client, "ALT-2026-001", add_flagged_domain)     # changed in the database, not via enrichment
    assert _audit(iso_client, "INCIDENT_STALE", inc) == []
    iso_client.post("/api/v1/pipeline/run")
    details = _details(iso_client, inc)
    assert any(f["type"] == "mock_intel" and "malicious-domain.net" in f["statement"] for f in details["investigation"]["findings"])
    assert details["investigation_stale"] is False
    (mark,) = _audit(iso_client, "INCIDENT_STALE", inc)
    assert mark["details"]["alert_id"] == "ALT-2026-001"
    before = len(_audit(iso_client, "INCIDENT_STALE", inc))
    iso_client.post("/api/v1/pipeline/run")
    assert len(_audit(iso_client, "INCIDENT_STALE", inc)) == before          # nothing new to catch the second time


def test_a_decided_incident_with_legacy_analysis_is_withdrawn_once_then_stays_stable(iso_client):
    _seed_and_run(iso_client)
    inc = _finance(iso_client)
    assert iso_client.post(f"/api/v1/incidents/{inc}/approve", json={"reviewer": "Analyst A"}).status_code == 200
    _edit_incident_details(iso_client, inc, lambda d: d.pop("analysis_basis", None))
    iso_client.post("/api/v1/pipeline/run")
    body = iso_client.get(f"/api/v1/incidents/{inc}").json()
    assert body["human_approval_status"] == "PENDING"
    assert body["details"]["review_history"][0]["review"]["decision"] == "APPROVED"
    assert "before change tracking" in body["details"]["review_history"][0]["superseded_by"]
    resets = _audit(iso_client, "APPROVAL_RESET", inc)
    assert len(resets) == 1
    iso_client.post("/api/v1/pipeline/run")
    assert len(_audit(iso_client, "APPROVAL_RESET", inc)) == 1               # not withdrawn again
    assert len(iso_client.get(f"/api/v1/incidents/{inc}").json()["details"]["review_history"]) == 1


def test_an_unchanged_pipeline_run_marks_nothing(iso_client, live):
    _seed_and_run(iso_client)
    live()
    iso_client.post("/api/v1/pipeline/run")
    again = iso_client.post("/api/v1/pipeline/run").json()
    assert all(s["processed"] == 0 for s in again["stages"])
    assert _audit(iso_client, "INCIDENT_STALE") == []
