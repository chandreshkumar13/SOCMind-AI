"""End-to-end workflow test for the Problem Statement ("Automated unit, integration, and end-to-end workflow tests").

One alert travels the whole SOCMind AI lifecycle through the public API only, and every step is asserted:

    ingest (POST /alerts with a custom alert, plus /alerts/seed) -> normalized fields -> triage score and priority
    -> enrichment IOCs (mock intelligence) -> correlation into an incident -> investigation (timeline and labelled findings)
    -> recommendations (human approval required, simulation only) -> approve -> simulate (nothing is executed)
    -> close an alert -> an audit-log entry for every major action.

It uses the isolated `iso_client` fixture (its own temporary database per test), so nothing touches socmind.db, and conftest.py
blocks all outbound network access, so no threat-intelligence provider is ever called. Threat intelligence is the offline mock.
"""
import pytest

API = "/api/v1"

# The custom alert. It shares its host, user and addresses with the seeded finance-workstation alerts, so correlation must put it
# in the same incident. Its timestamp is given with a +05:30 offset to show that ingest normalizes it to UTC.
CUSTOM_ALERT = {
    "id": "E2E-1",
    "alert_title": "Encoded PowerShell beacon on the finance workstation",
    "source": "CrowdStrike EDR",
    "raw_severity": "High",
    "host": "FINANCE-WKS-042",
    "username": "j.doe",
    "timestamp": "2026-09-03T14:00:00+05:30",
    "source_ip": "192.168.10.42",
    "destination_ip": "185.220.101.5",
    "command_line": "powershell.exe -NoProfile -EncodedCommand SQBFAFgA",
    "description": "Custom end-to-end alert",
}
SEEDED_FINANCE_ALERTS = {"ALT-2026-001", "ALT-2026-004", "ALT-2026-010"}
SEEDED_DOMAIN_CONTROLLER_ALERTS = {"ALT-2026-006", "ALT-2026-009"}
INTERNAL_HOST_IP = "192.168.10.42"          # the victim workstation: it must never be proposed as something to block
ATTACKER_IP = "185.220.101.5"               # the mock dataset's known command-and-control address
REVIEWER = "E2E Analyst"


def _incident_with(client, alert_id):
    return next(i for i in client.get(f"{API}/incidents").json() if alert_id in i["correlated_alert_ids"])


def _audit(client):
    rows = client.get(f"{API}/audit-logs", params={"limit": 200}).json()
    assert len(rows) < 200, "the audit log fits in one page, so every entry is checked"
    return rows


def _first_audit_id(rows, action, target=None):
    ids = [r["id"] for r in rows if r["action"] == action and (target is None or r["target_id"] == target)]
    assert ids, f"no audit entry {action} for {target}"
    return min(ids)


def test_one_alert_through_the_whole_lifecycle(iso_client):
    c = iso_client

    # ------------------------------------------------------------------ 1. ingest: seeded alerts and one custom alert
    seeded = c.post(f"{API}/alerts/seed")
    assert seeded.status_code == 200 and seeded.json()["inserted"] == 10 and seeded.json()["rejected"] == []

    ingested = c.post(f"{API}/alerts", json=CUSTOM_ALERT)
    assert ingested.status_code == 201
    alert = ingested.json()

    # ------------------------------------------------------------------ 2. normalized fields
    assert alert["id"] == "E2E-1" and alert["status"] == "NEW"
    assert alert["severity"] == "HIGH"                                            # "High" is normalized to the HIGH scale
    assert alert["normalized_data"]["raw_severity_input"] == "High"               # the original value is kept
    assert alert["timestamp"] == "2026-09-03T08:30:00Z"                           # +05:30 converted to explicit UTC
    assert alert["source"] == "CrowdStrike EDR" and alert["host"] == "FINANCE-WKS-042" and alert["destination_ip"] == ATTACKER_IP
    listing = c.get(f"{API}/alerts", params={"limit": 100})
    assert len(listing.json()) == 11 and listing.headers["X-Total-Count"] == "11"
    assert c.get(f"{API}/alerts", params={"status": "NEW"}).headers["X-Total-Count"] == "11"      # nothing analysed yet

    # ------------------------------------------------------------------ 3. triage: score and priority
    triaged = c.post(f"{API}/alerts/E2E-1/triage")
    assert triaged.status_code == 200
    triage_alert = triaged.json()["alert"]
    triage = triage_alert["normalized_data"]["triage"]
    assert triage_alert["status"] == "TRIAGED"
    assert 60 <= triage["suspicion_score"] <= 100 and triage["priority"] in ("HIGH", "CRITICAL")
    assert any("Encoded" in indicator for indicator in triage["indicators"])        # the encoded command was noticed
    assert triage["findings"] and all(f["type"] == "computed" for f in triage["findings"])   # rules on the alert's own fields, not intel

    # ------------------------------------------------------------------ 4. enrichment: IOCs from the mock intelligence
    enriched = c.post(f"{API}/alerts/E2E-1/enrich")
    assert enriched.status_code == 200
    enrichment = enriched.json()["enrichment_result"]
    assert enriched.json()["alert"]["status"] == "ENRICHED"
    assert enrichment["intel_mode"] == "mock" and enrichment["verified"] is False
    assert "LOCAL MOCK" in enrichment["disclaimer"]
    iocs = {i["value"]: i for i in enrichment["iocs"]}
    assert set(iocs) == {INTERNAL_HOST_IP, ATTACKER_IP} and enrichment["total_iocs_extracted"] == 2
    assert iocs[ATTACKER_IP]["reputation"] == "MALICIOUS" and iocs[ATTACKER_IP]["provider"] == "MockThreatIntel"
    assert iocs[INTERNAL_HOST_IP]["reputation"] == "CLEAN"                          # private address: a labelled mock answer
    assert enrichment["summary"] == {"malicious": 1, "suspicious": 0, "clean": 1, "unknown": 0}
    payloads = enrichment["encoded_payloads"]
    assert payloads and all(p["executed"] is False and "NOT executed" in p["provenance"] for p in payloads)   # decoded as text only

    # ------------------------------------------------------------------ 5. correlation: the pipeline links the alerts
    run = c.post(f"{API}/pipeline/run").json()
    assert run["outcome"] == "success" and run["status"] == "completed" and run["alerts_in_scope"] == 11
    assert len(run["incidents_created"]) == 2 and run["warnings"] == []
    finance = _incident_with(c, "E2E-1")
    assert set(finance["correlated_alert_ids"]) == SEEDED_FINANCE_ALERTS | {"E2E-1"}
    other = _incident_with(c, "ALT-2026-006")
    assert set(other["correlated_alert_ids"]) == SEEDED_DOMAIN_CONTROLLER_ALERTS and other["id"] != finance["id"]
    incident_id = finance["id"]
    detail = c.get(f"{API}/incidents/{incident_id}").json()
    correlation = detail["details"]["correlation"]
    assert correlation["shared_entities"]["host"] == ["FINANCE-WKS-042"] and correlation["alert_count"] == 4
    assert correlation["confidence"] == "high" and any("share host FINANCE-WKS-042" in r for r in correlation["reasons"])
    assert detail["status"] == "RESPONSE_PROPOSED" and detail["human_approval_status"] == "PENDING"

    # ------------------------------------------------------------------ 6. investigation: timeline and labelled findings
    investigation = detail["details"]["investigation"]
    assert investigation["status"] == "completed" and investigation["evidence_strength"] == "strong"
    times = [event["time"] for event in investigation["timeline"]]
    assert len(times) >= 4 and times == sorted(times)                              # chronological, alerts and log records together
    assert {e["type"] for e in investigation["timeline"]} == {"alert", "log"}
    findings = investigation["findings"]
    assert {f["type"] for f in findings} == {"verified", "mock_intel", "hypothesis"}   # no live intelligence in this run
    assert sum(investigation["counts"].values()) == len(findings)
    mock_findings = [f for f in findings if f["type"] == "mock_intel"]
    assert any(ATTACKER_IP in f["statement"] for f in mock_findings)
    assert all("MOCK" in f["statement"] and "Unverified" in f["statement"] for f in mock_findings)    # never presented as fact
    hypotheses = [f for f in findings if f["type"] == "hypothesis"]
    assert hypotheses and all(f["technique"].startswith("T1") for f in hypotheses)
    assert any("mock" in limitation.lower() for limitation in investigation["limitations"])

    # ------------------------------------------------------------------ 7. recommendations: human approval, simulation only
    recommendations = detail["details"]["recommendations"]
    response = detail["details"]["response"]
    assert recommendations
    assert response["requires_human_approval"] is True and response["execution_mode"] == "simulation_only"
    assert all(r["requires_approval"] is True and r["executed"] is False and r["status"] == "PENDING" for r in recommendations)
    targets = {r["target"] for r in recommendations}
    assert ATTACKER_IP in targets and INTERNAL_HOST_IP not in targets, "the attacker is the block target, never the victim host"
    assert any(r["category"] == "ioc_blocking" and r["target"] == ATTACKER_IP for r in recommendations)

    # ------------------------------------------------------------------ 8. approve: a human decision, still nothing executed
    approved = c.post(f"{API}/incidents/{incident_id}/approve", json={"reviewer": REVIEWER, "reason": "end-to-end test"})
    assert approved.status_code == 200
    body = approved.json()
    assert body["status"] == "RESPONSE_APPROVED" and body["human_approval_status"] == "APPROVED"
    review = body["details"]["review"]
    assert review["decision"] == "APPROVED" and review["reviewer"] == REVIEWER and "simulation_only" in review["execution"]
    assert all(r["status"] == "APPROVED" and r["executed"] is False for r in body["details"]["recommendations"])

    # ------------------------------------------------------------------ 9. simulate: a rehearsal on record, nothing executed
    simulated = c.post(f"{API}/incidents/{incident_id}/simulate", json={"reviewer": REVIEWER})
    assert simulated.status_code == 200
    sim_body = simulated.json()
    simulation = sim_body["details"]["simulation"]
    assert sim_body["status"] == "RESPONSE_SIMULATED" and simulation["mode"] == "simulation" and simulation["status"] == "SIMULATED"
    assert simulation["simulated_by"] == REVIEWER and len(simulation["actions"]) == len(recommendations)
    assert all(a["outcome"] == "Simulated only. No command was run and no system was changed." for a in simulation["actions"])
    assert all(r["executed"] is False and r["simulation_status"] == "SIMULATED" for r in sim_body["details"]["recommendations"])
    assert c.post(f"{API}/incidents/{incident_id}/simulate", json={"reviewer": REVIEWER}).status_code == 409   # only once

    # ------------------------------------------------------------------ 10. close an alert
    closed = c.delete(f"{API}/alerts/ALT-2026-004")
    assert closed.status_code == 200 and closed.json()["status"] == "success"
    assert closed.json()["incidents_updated"] == [incident_id]
    assert c.get(f"{API}/alerts/ALT-2026-004").json()["status"] == "CLOSED"       # closed, not deleted
    assert [a["id"] for a in c.get(f"{API}/alerts", params={"status": "CLOSED"}).json()] == ["ALT-2026-004"]
    after = c.get(f"{API}/incidents/{incident_id}").json()
    assert "ALT-2026-004" not in after["correlated_alert_ids"] and len(after["correlated_alert_ids"]) == 3
    assert after["details"]["closed_alerts"][0]["alert_id"] == "ALT-2026-004"
    # the decision was made on evidence that has changed, so it is withdrawn and the incident needs a fresh review
    assert after["human_approval_status"] == "PENDING" and after["status"] == "OPEN"
    assert after["details"]["investigation_stale"] is True and after["details"]["recommendations_stale"] is True
    assert len(after["details"]["review_history"]) == 1

    # ------------------------------------------------------------------ 11. audit log: every major action is recorded
    rows = _audit(c)
    actions = {r["action"] for r in rows}
    for expected in ("ALERTS_SEEDED", "ALERT_INGESTED", "ALERT_TRIAGED", "ALERT_ENRICHED", "PIPELINE_RUN", "INCIDENT_CREATED",
                     "INCIDENT_INVESTIGATED", "RESPONSE_RECOMMENDED", "INCIDENT_APPROVED", "RESPONSE_SIMULATED", "ALERT_CLOSED",
                     "INCIDENT_MEMBERSHIP_CHANGED", "APPROVAL_RESET"):
        assert expected in actions, f"{expected} is missing from the audit log"
    approval = next(r for r in rows if r["action"] == "INCIDENT_APPROVED")
    assert approval["actor"] == REVIEWER and approval["target_id"] == incident_id          # who decided, and on what
    assert next(r for r in rows if r["action"] == "ALERT_INGESTED" and r["target_id"] == "E2E-1")["actor"] == "API"
    assert next(r for r in rows if r["action"] == "ALERT_CLOSED")["target_id"] == "ALT-2026-004"
    assert next(r for r in rows if r["action"] == "RESPONSE_SIMULATED")["actor"] == REVIEWER
    assert {r["actor"] for r in rows if r["action"] == "ALERT_TRIAGED"} >= {"Triage Agent"}
    # and in the order the work was done
    order = [_first_audit_id(rows, a) for a in ("ALERTS_SEEDED", "ALERT_INGESTED", "PIPELINE_RUN", "INCIDENT_APPROVED", "RESPONSE_SIMULATED", "ALERT_CLOSED")]
    assert order == sorted(order), "audit entries follow the order of the lifecycle"
    assert not any("password" in str(r["details"]).lower() or "token" in str(r["details"]).lower() for r in rows)


def test_pipeline_report_and_statistics_follow_the_lifecycle(iso_client):
    """The same lifecycle seen from the pipeline report and the dashboard statistics, including a closed alert."""
    c = iso_client
    c.post(f"{API}/alerts/seed")

    run = c.post(f"{API}/pipeline/run").json()
    stages = {stage["agent"]: stage for stage in run["stages"]}
    assert set(stages) >= {"Triage Agent", "Enrichment Agent", "Correlation Agent", "Investigation Agent", "Response Agent"}
    assert all(stage["status"] == "success" and stage["errors"] == [] for stage in stages.values())
    assert stages["Triage Agent"]["processed"] == 10 and len(run["incidents_created"]) == 2

    rerun = c.post(f"{API}/pipeline/run").json()                                   # nothing new: a re-run changes nothing
    assert rerun["incidents_created"] == [] and all(stage["processed"] == 0 for stage in rerun["stages"])

    stats = c.get(f"{API}/stats").json()
    assert stats["alerts"]["total"] == 10 and stats["alerts"]["open"] == 10
    assert stats["incidents"]["total"] == 2 and stats["incidents"]["awaiting_human_review"] == 2

    incident_id = _incident_with(c, "ALT-2026-001")["id"]
    assert c.post(f"{API}/incidents/{incident_id}/approve", json={"reviewer": REVIEWER}).status_code == 200
    assert c.get(f"{API}/stats").json()["incidents"]["awaiting_human_review"] == 1      # one decided, one still waiting

    assert c.delete(f"{API}/alerts/ALT-2026-009").status_code == 200
    stats = c.get(f"{API}/stats").json()
    assert stats["alerts"]["total"] == 10 and stats["alerts"]["open"] == 9 and stats["alerts"]["by_status"]["CLOSED"] == 1

    # a closed alert is not brought back by running the work again
    c.post(f"{API}/alerts/ALT-2026-009/triage")
    c.post(f"{API}/pipeline/run")
    assert c.get(f"{API}/alerts/ALT-2026-009").json()["status"] == "CLOSED"
    assert "ALT-2026-009" not in _incident_with(c, "ALT-2026-006")["correlated_alert_ids"]
