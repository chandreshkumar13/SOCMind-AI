"""VirusTotal client: request shape, verdict mapping, error handling, quota, cache, eligibility and secrecy.

Everything uses httpx.MockTransport and a fake clock: no network, no real waiting.
"""
import json
import logging
import time

import httpx
import pytest

from vt_helpers import KEY, Clock, Server, payload
from app.tools.virustotal import (
    BASE_URL, RETRYABLE_STATUSES, STATUS_TEXT, Ineligible, QuotaLimiter, TTLCache, VirusTotalClient, prepare_ioc,
)

IP = "8.8.8.8"
SHA256 = "a" * 64


def make(server, clock=None, **kwargs):
    return VirusTotalClient(KEY, transport=httpx.MockTransport(server), clock=clock or Clock(), **kwargs)


@pytest.fixture(autouse=True)
def never_sleeps(monkeypatch):
    """The client must answer 'not now' instead of waiting for quota."""
    def boom(*a, **k):
        raise AssertionError("time.sleep was called")
    monkeypatch.setattr(time, "sleep", boom)


# ------------------------------------------------------------------ request shape
def test_ip_lookup_request_shape():
    server = Server()
    result = make(server).lookup("IP", IP)
    (req,) = server.requests
    assert req.method == "GET" and str(req.url) == f"{BASE_URL}/ip_addresses/{IP}"
    assert req.headers["x-apikey"] == KEY and KEY not in str(req.url)
    assert result["lookup_status"] == "completed" and result["provider"] == "VirusTotal" and result["request_made"] is True
    assert result["reference_url"] == f"https://www.virustotal.com/gui/ip-address/{IP}"


def test_hash_and_domain_use_their_own_collections():
    server = Server()
    client = make(server)
    client.lookup("SHA256", SHA256.upper())          # normalised to lower case
    client.lookup("MD5", "b" * 32)
    client.lookup("DOMAIN", "Evil-Domain.com.")      # normalised, trailing dot removed
    assert server.paths == [f"/api/v3/files/{SHA256}", f"/api/v3/files/{'b' * 32}", "/api/v3/domains/evil-domain.com"]


def test_ipv6_is_looked_up_in_compressed_form():
    server = Server()
    make(server).lookup("IP", "2606:4700:4700:0:0:0:0:1111")
    assert server.paths == ["/api/v3/ip_addresses/2606:4700:4700::1111"]


# ------------------------------------------------------------------ verdict mapping
@pytest.mark.parametrize("stats,threshold,expected,confidence", [
    (dict(malicious=3, harmless=60, undetected=7), 3, "MALICIOUS", 0.04),
    (dict(malicious=2, harmless=60, undetected=8), 3, "SUSPICIOUS", 0.03),
    (dict(malicious=0, suspicious=1, harmless=60, undetected=9), 3, "SUSPICIOUS", 0.01),
    (dict(malicious=1, harmless=60, undetected=9), 1, "MALICIOUS", 0.01),
    (dict(malicious=0, harmless=60, undetected=10), 3, "CLEAN", 0.5),
    (dict(malicious=0), 3, "UNKNOWN", 0.0),
])
def test_verdict_mapping_and_threshold(stats, threshold, expected, confidence):
    server = Server(lambda r: httpx.Response(200, json=payload(**stats)))
    result = make(server, malicious_threshold=threshold).lookup("IP", IP)
    assert result["reputation"] == expected and result["confidence"] == confidence
    assert result["detections"]["total"] == sum(stats.values())


def test_clean_is_never_described_as_safe():
    result = make(Server()).lookup("IP", IP)
    assert result["reputation"] == "CLEAN" and "not proof that it is safe" in result["evidence"]


def test_detecting_engines_are_listed_sanitised_and_capped():
    engines = [f"Engine{i}" for i in range(9)] + ["Bad\x00Name\n"]
    server = Server(lambda r: httpx.Response(200, json=payload(malicious=10, engines=engines)))
    result = make(server).lookup("IP", IP)
    assert len(result["detected_by"]) == 5 and all(e.isprintable() for e in result["detected_by"])


def test_result_carries_only_a_summary_not_the_raw_response():
    server = Server(lambda r: httpx.Response(200, json=payload(malicious=5, engines=[f"E{i}" for i in range(70)])))
    result = make(server).lookup("IP", IP)
    assert len(json.dumps(result)) < 1500 and set(result["detections"]) == {"malicious", "suspicious", "harmless", "undetected", "total"}
    assert result["retrieved_at"].endswith("Z")


# ------------------------------------------------------------------ errors
def test_not_found_is_unknown_and_cached_for_a_while():
    server = Server(lambda r: httpx.Response(404, json={"error": {"code": "NotFoundError", "message": "nope"}}))
    clock = Clock()
    client = make(server, clock)
    first = client.lookup("IP", IP)
    assert first["lookup_status"] == "not_found" and first["reputation"] == "UNKNOWN" and "not evidence" in first["evidence"]
    assert client.lookup("IP", IP)["cached"] is True and len(server.requests) == 1
    clock.advance(3601)
    client.lookup("IP", IP)
    assert len(server.requests) == 2


@pytest.mark.parametrize("status", [401, 403])
def test_a_rejected_key_stops_all_further_requests(status):
    server = Server(lambda r: httpx.Response(status, json={"error": {"code": "WrongCredentialsError", "message": f"bad key {KEY}"}}))
    client = make(server)
    first = client.lookup("IP", IP)
    assert first["lookup_status"] == "auth_error" and "VIRUSTOTAL_API_KEY" in first["evidence"] and KEY not in json.dumps(first)
    assert client.lookup("SHA256", SHA256)["lookup_status"] == "auth_error"
    assert len(server.requests) == 1


def test_429_with_retry_after_pauses_everything_until_it_expires():
    server = Server(lambda r: httpx.Response(429, headers={"Retry-After": "120"}, json={"error": {"code": "QuotaExceededError"}}))
    clock = Clock()
    client = make(server, clock, per_minute=100)
    assert client.lookup("IP", IP)["lookup_status"] == "rate_limited"
    clock.advance(119)
    assert client.lookup("SHA256", SHA256)["lookup_status"] == "rate_limited" and len(server.requests) == 1    # no request while paused
    assert client.limiter.snapshot()["paused_for_seconds"] == 1
    clock.advance(2)
    server.respond = lambda r: httpx.Response(200, json=payload(harmless=5))
    assert client.lookup("SHA256", SHA256)["lookup_status"] == "completed"


def test_429_without_retry_after_defaults_to_a_minute():
    server = Server(lambda r: httpx.Response(429, json={"error": {"code": "TooManyRequestsError", "message": "slow down"}}))
    clock = Clock()
    client = make(server, clock, per_minute=100)
    client.lookup("IP", IP)
    assert client.limiter.snapshot()["paused_for_seconds"] == 60


def test_daily_quota_error_pauses_until_midnight_utc():
    server = Server(lambda r: httpx.Response(429, json={"error": {"code": "QuotaExceededError", "message": "Daily quota exceeded"}}))
    client = make(server, Clock(1_700_000_000.0))     # 2023-11-14 22:13:20 UTC -> 1h46m40s to midnight
    client.lookup("IP", IP)
    assert 6000 <= client.limiter.snapshot()["paused_for_seconds"] <= 6400


@pytest.mark.parametrize("respond", [
    lambda r: httpx.Response(500, text="boom"),
    lambda r: httpx.Response(503, json={"error": {"code": "TransientError"}}),
    lambda r: httpx.Response(200, text="<html>not json</html>"),
    lambda r: httpx.Response(200, json={"data": {}}),
    lambda r: httpx.Response(200, json=payload(malicious=-4)),
    lambda r: httpx.Response(302, headers={"Location": "https://evil.example.net/steal"}),
    lambda r: (_ for _ in ()).throw(httpx.ConnectError("no route")),
])
def test_bad_answers_are_reported_as_retryable_errors(respond):
    server = Server(respond)
    result = make(server).lookup("IP", IP)
    assert result["lookup_status"] == "error" and result["reputation"] == "UNKNOWN" and "error" in RETRYABLE_STATUSES
    assert len(server.requests) == 1                      # redirects are not followed


def test_timeout_is_reported_and_retryable():
    def slow(request):
        raise httpx.ReadTimeout("too slow")
    result = make(Server(slow)).lookup("IP", IP)
    assert result["lookup_status"] == "timeout" and "timeout" in RETRYABLE_STATUSES


def test_circuit_opens_after_repeated_failures_and_recovers():
    server = Server(lambda r: httpx.Response(503))
    clock = Clock()
    client = make(server, clock, per_minute=100)
    for i in range(3):
        assert client.lookup("IP", f"8.8.8.{i + 1}")["lookup_status"] == "error"
    assert client.lookup("IP", "8.8.8.9")["lookup_status"] == "circuit_open" and len(server.requests) == 3
    clock.advance(61)
    server.respond = lambda r: httpx.Response(200, json=payload(harmless=5))
    assert client.lookup("IP", "8.8.8.9")["lookup_status"] == "completed"


def test_a_success_resets_the_failure_count():
    outcomes = iter([503, 503, 200, 503, 503, 200])
    server = Server(lambda r: (lambda s: httpx.Response(s, json=payload(harmless=5)) if s == 200 else httpx.Response(s))(next(outcomes)))
    client = make(server, per_minute=100)
    results = [client.lookup("IP", f"8.8.8.{i + 1}")["lookup_status"] for i in range(6)]
    assert results == ["error", "error", "completed", "error", "error", "completed"]


# ------------------------------------------------------------------ cache
def test_completed_lookups_are_cached_case_insensitively_until_the_ttl():
    server = Server()
    clock = Clock()
    client = make(server, clock, cache_ttl=100)
    assert client.lookup("SHA256", SHA256)["cached"] is False
    again = client.lookup("SHA256", SHA256.upper())
    assert again["cached"] is True and again["request_made"] is False and len(server.requests) == 1
    clock.advance(101)
    assert client.lookup("SHA256", SHA256)["cached"] is False and len(server.requests) == 2


def test_failures_are_not_cached():
    server = Server(lambda r: httpx.Response(503))
    client = make(server, per_minute=100)
    client.lookup("IP", IP)
    client.lookup("IP", IP)
    assert len(server.requests) == 2 and len(client.cache) == 0


def test_cache_is_bounded():
    cache = TTLCache(ttl=1000, clock=Clock(), max_items=3)
    for i in range(10):
        cache.set(i, {"v": i})
    assert len(cache) == 3


# ------------------------------------------------------------------ quota
def test_per_minute_quota_is_enforced_without_sleeping():
    server = Server()
    clock = Clock()
    client = make(server, clock, per_minute=4, per_day=500)
    statuses = [client.lookup("IP", f"8.8.4.{i + 1}")["lookup_status"] for i in range(6)]
    assert statuses == ["completed"] * 4 + ["rate_limited"] * 2 and len(server.requests) == 4
    clock.advance(60)
    assert client.lookup("IP", "8.8.4.5")["lookup_status"] == "completed"


def test_per_day_quota_is_enforced():
    server = Server()
    clock = Clock()
    client = make(server, clock, per_minute=100, per_day=3)
    for i in range(3):
        client.lookup("IP", f"8.8.4.{i + 1}")
    assert client.lookup("IP", "8.8.4.9")["lookup_status"] == "rate_limited"
    clock.advance(3600)
    assert client.lookup("IP", "8.8.4.9")["lookup_status"] == "rate_limited"
    clock.advance(86400)
    assert client.lookup("IP", "8.8.4.9")["lookup_status"] == "completed"


def test_quota_snapshot_reports_usage():
    client = make(Server(), per_minute=4, per_day=500)
    client.lookup("IP", IP)
    assert client.limiter.snapshot() == {"used_last_minute": 1, "used_last_24h": 1, "per_minute": 4, "per_day": 500, "paused_for_seconds": 0}


def test_allow_request_false_still_serves_the_cache_but_never_the_network():
    server = Server()
    client = make(server)
    client.lookup("IP", IP)
    assert client.lookup("IP", IP, allow_request=False)["cached"] is True
    other = client.lookup("IP", "8.8.4.4", allow_request=False)
    assert other["lookup_status"] == "budget_exceeded" and len(server.requests) == 1


def test_limiter_unit():
    clock = Clock()
    limiter = QuotaLimiter(2, 5, clock)
    assert [limiter.try_acquire() for _ in range(3)] == [True, True, False]
    limiter.block_for(30)
    clock.advance(61)
    assert limiter.try_acquire() is True       # minute window and the 30 s pause are both over


# ------------------------------------------------------------------ what may leave the network
@pytest.mark.parametrize("ip", [
    "10.0.0.1", "192.168.1.1", "172.16.5.4", "127.0.0.1", "169.254.1.1", "100.64.0.1", "0.0.0.0", "224.0.0.1", "240.0.0.1",
    "198.51.100.77", "203.0.113.88", "192.0.2.1", "::1", "fe80::1", "fc00::1", "2001:db8::1", "::ffff:10.0.0.1", "::",
    "not-an-ip", "", "8.8.8.8%eth0", "8.8.8.8/../../x",
])
def test_non_public_or_invalid_ips_are_never_sent(ip):
    server = Server()
    result = make(server).lookup("IP", ip)
    assert server.requests == [] and result["lookup_status"] in ("skipped_non_public_ip", "skipped_invalid")
    assert result["reputation"] == "UNKNOWN" and result["provider"] == "none" and result["request_made"] is False


@pytest.mark.parametrize("domain", [
    "j.doe", "host.local", "server.internal", "printer.lan", "localhost", "example.com", "a.example.org", "install.sh", "readme.md",
    "script.py", "-bad.com", "bad_.com", "a..com", "nodot", "evil.com/path", "evil.com?x=1", "user@evil.com", "1.2.3.4",
    "a" * 64 + ".com", "evil.com:8080", "ev il.com", "",
])
def test_ineligible_domains_are_never_sent(domain):
    server = Server()
    result = make(server).lookup("DOMAIN", domain)
    assert server.requests == [] and result["lookup_status"].startswith("skipped")


@pytest.mark.parametrize("domain", ["evil-domain.com", "Sub.Evil.co.uk", "c2.example-bad.io", "malware.ru"])
def test_public_domains_are_eligible(domain):
    assert prepare_ioc("DOMAIN", domain)[0] == "domains"


def test_invalid_hashes_urls_and_unknown_types_are_never_sent():
    server = Server()
    client = make(server)
    assert client.lookup("SHA256", "z" * 64)["lookup_status"] == "skipped_invalid"
    assert client.lookup("MD5", "a" * 31)["lookup_status"] == "skipped_invalid"
    assert client.lookup("URL", "http://evil-domain.com/payload.exe?token=secret")["lookup_status"] == "skipped_url"
    assert client.lookup("EMAIL", "a@b.com")["lookup_status"] == "skipped_unsupported"
    assert server.requests == []


def test_public_ips_are_eligible():
    assert prepare_ioc("IP", "8.8.8.8") == ("ip_addresses", "8.8.8.8")
    assert prepare_ioc("IP", "2606:4700:4700::1111")[0] == "ip_addresses"
    with pytest.raises(Ineligible):
        prepare_ioc("IP", "10.1.2.3")


def test_every_status_has_user_facing_text():
    assert RETRYABLE_STATUSES <= set(STATUS_TEXT)
    assert all(text.strip() for text in STATUS_TEXT.values())


# ------------------------------------------------------------------ secrecy
def test_the_api_key_never_appears_in_results_reprs_or_logs(caplog):
    caplog.set_level(logging.DEBUG)
    echo = lambda status: (lambda r: httpx.Response(status, headers={"Retry-After": "5"}, json={"error": {"message": f"key {r.headers['x-apikey']} rejected"}}))
    seen = []
    for respond in (lambda r: httpx.Response(200, json=payload(malicious=9)), echo(401), echo(429), echo(503),
                    lambda r: (_ for _ in ()).throw(httpx.ReadTimeout(f"timeout using {r.headers['x-apikey']}"))):
        client = make(Server(respond), per_minute=100)
        seen.append(client.lookup("IP", IP))
        seen.append(repr(client))
    blob = json.dumps(seen, default=str) + caplog.text
    assert KEY not in blob and "x-apikey" not in blob.lower()


def test_blank_keys_are_rejected():
    for key in ("", "   ", None):
        with pytest.raises(ValueError):
            VirusTotalClient(key)


def test_the_base_url_cannot_be_influenced_by_indicator_values():
    server = Server()
    client = make(server)
    for value in ("evil.com/../../v2/x", "evil.com@attacker.net", "//attacker.net/x"):
        client.lookup("DOMAIN", value)
    assert server.requests == []
    client.lookup("IP", IP)
    assert server.requests[0].url.host == "www.virustotal.com"
