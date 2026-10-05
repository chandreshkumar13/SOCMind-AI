import pytest
from fastapi.testclient import TestClient
from app.main import app
from app.agents.triage.triage_agent import TriageAgent
from app.db.session import init_db

init_db()
client = TestClient(app)


def test_severity_base_priority_differences():
    agent = TriageAgent()
    crit_alert = {"alert_title": "Generic Alert", "severity": "CRITICAL"}
    low_alert = {"alert_title": "Generic Alert", "severity": "LOW"}

    crit_res = agent.analyze_alert(crit_alert)
    low_res = agent.analyze_alert(low_alert)

    assert crit_res["suspicion_score"] > low_res["suspicion_score"]
    assert crit_res["assigned_severity"] == "CRITICAL"
    assert low_res["assigned_severity"] == "LOW"


def test_suspicious_command_line_indicator_increases_score():
    agent = TriageAgent()
    base_alert = {"alert_title": "PowerShell execution", "severity": "MEDIUM"}
    suspicious_cmd_alert = {
        "alert_title": "PowerShell execution",
        "severity": "MEDIUM",
        "command_line": "powershell.exe -ExecutionPolicy Bypass -e aW52b2tlLXdlYnJlcXVlc3Q="
    }

    base_res = agent.analyze_alert(base_alert)
    sus_res = agent.analyze_alert(suspicious_cmd_alert)

    assert sus_res["suspicion_score"] > base_res["suspicion_score"]
    assert any("Encoded" in ind or "bypass" in ind for ind in sus_res["indicators"])


def test_suspicious_keywords_detection():
    agent = TriageAgent()
    ransomware_alert = {
        "alert_title": "Rapid bulk file encryption (Ransomware heuristic)",
        "description": "C2 beaconing activity detected on host",
        "severity": "HIGH",
        "source_ip": "192.168.1.50"
    }

    res = agent.analyze_alert(ransomware_alert)
    assert any("keyword matched" in ind for ind in res["indicators"])
    assert res["suspicion_score"] >= 60  # 35 (HIGH) + 20 (Ransomware/C2 keyword) + 5 (Source IP) = 60


def test_score_never_exceeds_100():
    agent = TriageAgent()
    extreme_alert = {
        "alert_title": "Ransomware C2 Beaconing Exfiltration Privilege Escalation",
        "description": "Unusual failed ssh brute force kerberoasting",
        "severity": "CRITICAL",
        "source_ip": "192.168.1.100",
        "destination_ip": "185.220.101.5",
        "file_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "command_line": "powershell.exe -e aW52b2tl minidump reg.exe add downloadstring -ExecutionPolicy Bypass",
        "username": "administrator"
    }

    res = agent.analyze_alert(extreme_alert)
    assert res["suspicion_score"] <= 100
    assert res["suspicion_score"] == 100
    assert res["priority"] == "CRITICAL"


def test_triage_returns_human_readable_rationale():
    agent = TriageAgent()
    alert = {
        "alert_title": "Suspicious Process Execution",
        "severity": "HIGH",
        "source_ip": "10.0.0.5"
    }

    res = agent.analyze_alert(alert)
    assert "rationale" in res
    assert len(res["rationale"]) > 20
    assert "Base severity signal" in res["rationale"]


def test_triage_api_endpoint_success():
    # Ingest a new alert first
    ingest_payload = {
        "alert_title": "Phase 3.1 Test Alert For Triage API",
        "source": "CrowdStrike EDR",
        "severity": "HIGH",
        "command_line": "powershell.exe -e aW52b2tl"
    }
    ingest_res = client.post("/api/v1/alerts", json=ingest_payload)
    assert ingest_res.status_code == 201
    alert_id = ingest_res.json()["id"]
    assert ingest_res.json()["status"] == "NEW"

    # Call POST /api/v1/alerts/{alert_id}/triage
    triage_res = client.post(f"/api/v1/alerts/{alert_id}/triage")
    assert triage_res.status_code == 200
    data = triage_res.json()

    assert "alert" in data
    assert "triage_result" in data
    assert data["alert"]["status"] == "TRIAGED"
    assert data["triage_result"]["alert_id"] == alert_id
    assert data["triage_result"]["agent"] == "Triage Agent"
    assert data["triage_result"]["suspicion_score"] >= 35

    # Verify database record updated
    get_res = client.get(f"/api/v1/alerts/{alert_id}")
    assert get_res.status_code == 200
    assert get_res.json()["status"] == "TRIAGED"
    assert "triage" in get_res.json()["normalized_data"]


def test_triage_api_endpoint_404():
    response = client.post("/api/v1/alerts/NON-EXISTENT-ALERT-999/triage")
    assert response.status_code == 404
    assert "not found" in response.json()["detail"].lower()
