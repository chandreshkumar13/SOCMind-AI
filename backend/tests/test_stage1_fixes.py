from app.services.normalization import NormalizationService as NS


def test_microsoft_sentinel_is_not_mapped_to_defender():
    assert NS.normalize_source("Microsoft Sentinel") == "Microsoft Sentinel"
    assert NS.normalize_source("Microsoft Defender for Cloud") == "Microsoft Defender"


def test_pan_substring_does_not_match_unrelated_names():
    assert NS.normalize_source("Company Panel Tool") == "Company Panel Tool"
    assert NS.normalize_source("Palo Alto Networks") == "Palo Alto Firewall"
    assert NS.normalize_source("PAN-OS") == "Palo Alto Firewall"


def test_sentinelone_still_mapped():
    assert NS.normalize_source("SentinelOne EDR") == "SentinelOne"


def test_numeric_severity_codes_complete():
    assert NS.normalize_severity("9") == "CRITICAL"
    assert NS.normalize_severity("6") == "MEDIUM"


def test_triage_does_not_reopen_closed_alert(iso_client):
    iso_client.post("/api/v1/alerts/seed")
    iso_client.delete("/api/v1/alerts/ALT-2026-002")
    res = iso_client.post("/api/v1/alerts/ALT-2026-002/triage")
    assert res.status_code == 200
    assert res.json()["alert"]["status"] == "CLOSED"
    assert res.json()["triage_result"]["suspicion_score"] > 0


def test_health_does_not_expose_database_url(iso_client):
    body = iso_client.get("/api/v1/health").json()
    assert body["database"] == "sqlite"
    assert "///" not in str(body)
