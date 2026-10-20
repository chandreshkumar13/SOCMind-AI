from app.agents.enrichment.enrichment_agent import EnrichmentAgent


def test_extracts_ips_hashes_and_ignores_file_names():
    alert = {"source_ip": "192.168.10.42", "destination_ip": "185.220.101.5",
             "file_hash": "2b8a741369359e19864293fe2f7cfef5f58c70425712ef9e3dfa4b13a8efee5d",
             "command_line": r"rundll32.exe C:\Users\Public\Temp\update.dll,Start"}
    iocs = EnrichmentAgent().extract_iocs(alert)
    kinds = {(i["type"], i["value"]) for i in iocs}
    assert ("IP", "185.220.101.5") in kinds and ("SHA256", alert["file_hash"]) in kinds
    assert not any(i["type"] == "DOMAIN" for i in iocs)   # update.dll must not be treated as a domain


def test_internal_and_public_ips_get_different_reputations():
    iocs = EnrichmentAgent().enrich_alert({"source_ip": "10.0.1.15", "destination_ip": "185.220.101.5"})["iocs"]
    by_value = {i["value"]: i["reputation"] for i in iocs}
    assert by_value == {"10.0.1.15": "CLEAN", "185.220.101.5": "MALICIOUS"}


def _enrich(client, **fields):
    alert = {"alert_title": "t", **fields}
    alert_id = client.post("/api/v1/alerts", json=alert).json()["id"]
    res = client.post(f"/api/v1/alerts/{alert_id}/enrich")
    assert res.status_code == 200
    return alert_id, res.json()


def test_enrichment_is_labelled_mock_and_unverified_and_clean_is_not_safe(iso_client):
    _, body = _enrich(iso_client, source_ip="192.168.10.42", destination_ip="185.220.101.5")
    result = body["enrichment_result"]
    assert result["verified"] is False and result["intel_mode"] == "mock"
    assert "MOCK" in result["disclaimer"] and "not mean the indicator is verified safe" in result["disclaimer"]
    by_value = {i["value"]: i for i in result["iocs"]}
    assert by_value["192.168.10.42"]["reputation"] == "CLEAN"
    assert by_value["185.220.101.5"]["reputation"] == "MALICIOUS"
    assert result["summary"]["malicious"] == 1


def test_unknown_public_ioc_is_unknown_not_clean(iso_client):
    _, body = _enrich(iso_client, destination_ip="8.8.8.8")
    assert body["enrichment_result"]["iocs"][0]["reputation"] == "UNKNOWN"


def test_empty_alert_has_no_iocs():
    assert EnrichmentAgent().enrich_alert({})["total_iocs_extracted"] == 0


def test_enrich_endpoint_persists_result_and_audits(iso_client):
    iso_client.post("/api/v1/alerts/seed")
    res = iso_client.post("/api/v1/alerts/ALT-2026-001/enrich")
    assert res.status_code == 200
    body = res.json()
    assert body["enrichment_result"]["summary"]["malicious"] >= 1
    assert body["alert"]["normalized_data"]["enrichment"]["verified"] is False
    logs = iso_client.get("/api/v1/audit-logs", params={"action": "ALERT_ENRICHED"}).json()
    assert logs and logs[0]["target_id"] == "ALT-2026-001" and logs[0]["actor"] == "Enrichment Agent"


def test_enrich_unknown_alert_404_and_closed_alert_stays_closed(iso_client):
    assert iso_client.post("/api/v1/alerts/NOPE/enrich").status_code == 404
    alert_id, _ = _enrich(iso_client, source_ip="185.220.101.5")
    iso_client.delete(f"/api/v1/alerts/{alert_id}")
    res = iso_client.post(f"/api/v1/alerts/{alert_id}/enrich")
    assert res.status_code == 200
    assert res.json()["alert"]["status"] == "CLOSED"
    assert res.json()["enrichment_result"]["summary"]["malicious"] == 1


def test_ingest_triage_close_are_audited(iso_client):
    iso_client.post("/api/v1/alerts", json={"id": "T-1", "alert_title": "x"})
    iso_client.post("/api/v1/alerts/T-1/triage")
    iso_client.delete("/api/v1/alerts/T-1")
    actions = [l["action"] for l in iso_client.get("/api/v1/audit-logs", params={"target_id": "T-1"}).json()]
    assert {"ALERT_INGESTED", "ALERT_TRIAGED", "ALERT_CLOSED"} <= set(actions)
