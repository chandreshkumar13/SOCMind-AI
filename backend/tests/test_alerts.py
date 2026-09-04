import pytest
from fastapi.testclient import TestClient
from app.main import app
from app.db.session import init_db

# Ensure database tables exist for tests
init_db()

client = TestClient(app)


def test_health_check():
    response = client.get("/api/v1/health")
    assert response.status_code == 200
    assert response.json()["status"] == "healthy"


def test_version_check():
    response = client.get("/api/v1/version")
    assert response.status_code == 200
    assert response.json()["version"] == "1.0.0"


def test_seed_alerts():
    # First seed call
    res = client.post("/api/v1/alerts/seed")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "success"
    assert data["inserted"] >= 1

    # Second seed call (idempotent duplicate protection check)
    res_dup = client.post("/api/v1/alerts/seed")
    assert res_dup.status_code == 200
    data_dup = res_dup.json()
    assert data_dup["inserted"] == 0
    assert data_dup["skipped"] == data["total_processed"]


def test_get_alerts_list():
    response = client.get("/api/v1/alerts")
    assert response.status_code == 200
    alerts = response.json()
    assert isinstance(alerts, list)
    assert len(alerts) >= 5


def test_get_single_alert():
    # Fetch first alert from list
    res_list = client.get("/api/v1/alerts")
    alert_id = res_list.json()[0]["id"]

    res_single = client.get(f"/api/v1/alerts/{alert_id}")
    assert res_single.status_code == 200
    data = res_single.json()
    assert data["id"] == alert_id
    assert "alert_title" in data
    assert "severity" in data


def test_single_alert_not_found():
    response = client.get("/api/v1/alerts/NON-EXISTENT-999")
    assert response.status_code == 404


def test_severity_filtering():
    response = client.get("/api/v1/alerts?severity=CRITICAL")
    assert response.status_code == 200
    alerts = response.json()
    for a in alerts:
        assert a["severity"] == "CRITICAL"


def test_search_functionality():
    response = client.get("/api/v1/alerts?search=PowerShell")
    assert response.status_code == 200
    alerts = response.json()
    assert len(alerts) >= 1
    assert "powershell" in alerts[0]["alert_title"].lower() or "powershell" in (alerts[0]["command_line"] or "").lower()


def test_valid_alert_ingestion_and_normalization():
    payload = {
        "alert_title": "Test Custom Ransomware Warning",
        "source_system": "CrowdStrike Falcon EDR",
        "raw_severity": "10",
        "host_name": "TEST-HOST-99",
        "user": "test.user",
        "command_line": "cmd.exe /c test_payload.bat"
    }

    response = client.post("/api/v1/alerts", json=payload)
    assert response.status_code == 201
    data = response.json()
    assert data["alert_title"] == "Test Custom Ransomware Warning"
    assert data["severity"] == "CRITICAL"  # 10 maps to CRITICAL
    assert data["source"] == "CrowdStrike EDR"  # Source system mapped
    assert data["host"] == "TEST-HOST-99"
    assert data["status"] == "NEW"


def test_delete_close_alert():
    # Ingest a temporary test alert
    payload = {
        "alert_title": "Temporary Test Alert To Delete",
        "source": "Splunk SIEM",
        "severity": "LOW"
    }
    create_res = client.post("/api/v1/alerts", json=payload)
    alert_id = create_res.json()["id"]

    # Close alert via DELETE endpoint
    del_res = client.delete(f"/api/v1/alerts/{alert_id}")
    assert del_res.status_code == 200
    assert del_res.json()["status"] == "success"

    # Verify status changed to CLOSED in database
    get_res = client.get(f"/api/v1/alerts/{alert_id}")
    assert get_res.json()["status"] == "CLOSED"
