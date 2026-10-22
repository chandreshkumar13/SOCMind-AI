from app.agents.investigation.investigation_agent import InvestigationAgent
from app.services.log_store import load_sample_logs


def _ready(client):
    client.post("/api/v1/alerts/seed")
    client.post("/api/v1/alerts/ALT-2026-001/enrich")
    client.post("/api/v1/alerts/ALT-2026-004/enrich")
    client.post("/api/v1/incidents/correlate")
    return [i for i in client.get("/api/v1/incidents").json() if "ALT-2026-001" in i["correlated_alert_ids"]][0]["id"]


def test_sample_logs_load():
    assert len(load_sample_logs()) >= 4


def test_investigate_builds_timeline_with_alerts_and_logs(iso_client):
    inc_id = _ready(iso_client)
    res = iso_client.post(f"/api/v1/incidents/{inc_id}/investigate")
    assert res.status_code == 200
    inv = res.json()["details"]["investigation"]
    types = {e["type"] for e in inv["timeline"]}
    assert types == {"alert", "log"}
    times = [e["time"] for e in inv["timeline"]]
    assert times == sorted(times)
    assert inv["evidence_strength"] == "strong"
    assert res.json()["status"] == "INVESTIGATED" and "Evidence strength" in res.json()["ai_summary"]


def test_findings_are_labelled_and_hypotheses_never_high_confidence(iso_client):
    inc_id = _ready(iso_client)
    inv = iso_client.post(f"/api/v1/incidents/{inc_id}/investigate").json()["details"]["investigation"]
    kinds = {f["type"] for f in inv["findings"]}
    assert {"verified", "mock_intel", "hypothesis"} <= kinds
    hyps = [f for f in inv["findings"] if f["type"] == "hypothesis"]
    assert hyps and all(h["confidence"] in ("low", "medium") for h in hyps)
    assert any(h["technique"] == "T1059.001" for h in hyps)
    assert all("Unverified" in f["statement"] for f in inv["findings"] if f["type"] == "mock_intel")


def test_log_corroboration_is_verified_not_hypothesis(iso_client):
    inc_id = _ready(iso_client)
    inv = iso_client.post(f"/api/v1/incidents/{inc_id}/investigate").json()["details"]["investigation"]
    assert any(f["type"] == "verified" and f["basis"] and f["basis"][0].startswith("log:") for f in inv["findings"])


def test_no_logs_is_stated_explicitly():
    alerts = [{"id": "a", "timestamp": "2026-09-03T08:00:00Z", "host": "ZZZ", "alert_title": "x", "severity": "LOW"},
              {"id": "b", "timestamp": "2026-09-03T08:05:00Z", "host": "ZZZ", "alert_title": "y", "severity": "LOW"}]
    inv = InvestigationAgent().investigate({"id": "INC-1"}, alerts, [])
    assert inv["log_records_used"] == 0 and inv["evidence_strength"] == "moderate"
    assert any("No matching log records" in f["statement"] for f in inv["findings"])


def test_single_alert_is_weak_evidence():
    inv = InvestigationAgent().investigate({"id": "INC-1"}, [{"id": "a", "timestamp": "2026-09-03T08:00:00Z", "host": "H", "alert_title": "x"}], [])
    assert inv["evidence_strength"] == "weak"


def test_investigate_unknown_incident_404(iso_client):
    assert iso_client.post("/api/v1/incidents/NOPE/investigate").status_code == 404


def test_investigation_is_audited_and_repeatable(iso_client):
    inc_id = _ready(iso_client)
    a = iso_client.post(f"/api/v1/incidents/{inc_id}/investigate").json()["ai_summary"]
    b = iso_client.post(f"/api/v1/incidents/{inc_id}/investigate").json()["ai_summary"]
    assert a == b
    logs = iso_client.get("/api/v1/audit-logs", params={"target_id": inc_id, "action": "INCIDENT_INVESTIGATED"}).json()
    assert len(logs) == 2 and logs[0]["actor"] == "Investigation Agent"


def test_process_name_alone_is_not_an_lsass_dump_hypothesis():
    alerts = [{"id": "a", "timestamp": "2026-09-03T08:00:00Z", "host": "DC", "alert_title": "Unusual login", "command_line": "C:\\Windows\\System32\\lsass.exe", "severity": "HIGH"},
              {"id": "b", "timestamp": "2026-09-03T08:05:00Z", "host": "DC", "alert_title": "Other", "severity": "LOW"}]
    techniques = {f.get("technique") for f in InvestigationAgent().investigate({"id": "I"}, alerts, [])["findings"]}
    assert "T1003.001" not in techniques


def test_real_lsass_dump_alert_is_a_hypothesis():
    alerts = [{"id": "a", "timestamp": "2026-09-03T08:00:00Z", "host": "DEV", "alert_title": "LSASS Process Memory Dump Attempt Detected",
               "command_line": "rundll32.exe comsvcs.dll, MiniDump 672 C:\\Users\\Public\\lsass.dmp full", "severity": "CRITICAL"},
              {"id": "b", "timestamp": "2026-09-03T08:05:00Z", "host": "DEV", "alert_title": "Other", "severity": "LOW"}]
    techniques = {f.get("technique") for f in InvestigationAgent().investigate({"id": "I"}, alerts, [])["findings"]}
    assert "T1003.001" in techniques
