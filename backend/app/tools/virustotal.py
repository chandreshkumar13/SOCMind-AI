"""VirusTotal (public API v3) reputation lookups.

Design rules
- Opt-in and polite: this module only makes a request when it is asked to, never sleeps to wait for quota, and
  never sends private, loopback, reserved or otherwise non-public indicators to a third party.
- The API key lives only in the request header. It is never put in a URL, a result, a log line or an exception
  message; failures are reported as fixed status strings (see STATUS_TEXT), never with raw server or library text.
- Expected failures (rate limit, timeout, not found, ...) are returned as results with a `lookup_status`, not raised,
  so one bad indicator cannot break the enrichment of an alert.
- The base URL is a constant: indicator values come from untrusted alert text and must never influence the host.

Not implemented on purpose: URL lookups (query strings can carry internal tokens), uploads/scans, and any action
against the indicators. Reading a report is the only thing this module does.
"""
import ipaddress
import logging
import re
import threading
import time
from collections import deque
from datetime import datetime, timezone
from typing import Any, Callable, Dict, Optional, Tuple
from urllib.parse import quote

import httpx

logger = logging.getLogger("socmind.intel")

BASE_URL = "https://www.virustotal.com/api/v3"
GUI_URL = "https://www.virustotal.com/gui"
PROVIDER = "VirusTotal"
MAX_DETECTED_BY = 5

# Statuses after which asking again later can give a different answer. Everything else is final for this alert.
RETRYABLE_STATUSES = frozenset({"rate_limited", "budget_exceeded", "timeout", "error", "circuit_open"})

STATUS_TEXT = {
    "completed": "Looked up on VirusTotal.",
    "not_found": "VirusTotal has no record of this indicator. That is not evidence that it is safe.",
    "rate_limited": "Not looked up: the VirusTotal request quota is used up for now. A later run will retry.",
    "budget_exceeded": "Not looked up: the per-alert lookup limit was reached. A later run will retry.",
    "timeout": "Not looked up: VirusTotal did not answer in time. A later run will retry.",
    "error": "Not looked up: VirusTotal could not be reached or returned an unusable answer. A later run will retry.",
    "circuit_open": "Not looked up: lookups are paused after repeated VirusTotal failures. A later run will retry.",
    "auth_error": "Not looked up: VirusTotal rejected the configured API key. Check VIRUSTOTAL_API_KEY.",
    "skipped_non_public_ip": "Not sent to VirusTotal: private, loopback, link-local, reserved or otherwise non-public address.",
    "skipped_invalid": "Not sent to VirusTotal: not a valid public indicator.",
    "skipped_unsupported": "Not sent to VirusTotal: this indicator type is not looked up.",
    "skipped_url": "Not sent to VirusTotal: URL lookups are disabled in this version.",
}

# ---- indicator eligibility ---------------------------------------------------------------------------------------
_HASH_RE = re.compile(r"[0-9a-f]{32}|[0-9a-f]{40}|[0-9a-f]{64}")
_LABEL_RE = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")
_GENERIC_TLDS = frozenset({
    "com", "net", "org", "info", "biz", "edu", "gov", "mil", "int", "io", "co", "app", "dev", "xyz", "online", "site",
    "tech", "cloud", "top", "club", "shop", "store", "live", "pro", "name", "mobi", "asia", "news", "blog", "page",
    "link", "click", "work", "space", "website", "email", "network", "systems", "services", "solutions",
})
# Two-letter country codes that are also common file extensions: "install.sh" is a file, not a domain.
_FILE_LIKE_TLDS = frozenset({"sh", "md", "py", "pl", "rs", "cs", "js", "ps", "ts", "rb", "pm", "so", "vb", "cc", "bat", "cmd"})
# Reserved or documentation-only names (RFC 2606 / 6761) that must never leave the network
_RESERVED_SUFFIXES = ("example.com", "example.net", "example.org", "localhost")


class Ineligible(Exception):
    """The indicator must not be sent to VirusTotal. `status` is a key of STATUS_TEXT."""

    def __init__(self, status: str):
        super().__init__(status)
        self.status = status


def prepare_ioc(ioc_type: str, value: Any) -> Tuple[str, str]:
    """Validates an indicator and returns (VirusTotal collection, normalized value) or raises Ineligible."""
    kind = str(ioc_type or "").upper()
    raw = str(value or "").strip()
    if kind == "URL":
        raise Ineligible("skipped_url")
    if kind == "IP":
        if not raw or "%" in raw:
            raise Ineligible("skipped_invalid")
        try:
            ip = ipaddress.ip_address(raw)
        except ValueError:
            raise Ineligible("skipped_invalid")
        mapped = getattr(ip, "ipv4_mapped", None)
        if mapped is not None:
            ip = mapped
        if (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved
                or ip.is_unspecified or not ip.is_global):
            raise Ineligible("skipped_non_public_ip")
        return "ip_addresses", ip.compressed
    if kind in ("MD5", "SHA1", "SHA256"):
        digest = raw.lower()
        if not _HASH_RE.fullmatch(digest):
            raise Ineligible("skipped_invalid")
        return "files", digest
    if kind == "DOMAIN":
        domain = raw.lower().rstrip(".")
        labels = domain.split(".")
        if len(domain) > 253 or len(labels) < 2 or not all(_LABEL_RE.fullmatch(label) for label in labels):
            raise Ineligible("skipped_invalid")
        tld = labels[-1]
        if tld in _FILE_LIKE_TLDS or not (tld in _GENERIC_TLDS or (len(tld) == 2 and tld.isalpha())):
            raise Ineligible("skipped_invalid")
        if any(domain == s or domain.endswith("." + s) for s in _RESERVED_SUFFIXES):
            raise Ineligible("skipped_invalid")
        return "domains", domain
    raise Ineligible("skipped_unsupported")


def reference_url(collection: str, value: str) -> str:
    segment = {"ip_addresses": "ip-address", "domains": "domain", "files": "file"}[collection]
    return f"{GUI_URL}/{segment}/{quote(value, safe=':')}"


# ---- quota, cache, circuit breaker ----------------------------------------------------------------------------------
class QuotaLimiter:
    """Sliding-window request budget (public API: 4/minute, 500/day). Never sleeps: it only answers yes or no."""

    def __init__(self, per_minute: int, per_day: int, clock: Callable[[], float] = time.time):
        self.per_minute, self.per_day, self._clock = max(1, per_minute), max(1, per_day), clock
        self._minute: deque = deque()
        self._day: deque = deque()
        self._blocked_until = 0.0
        self._lock = threading.Lock()

    def _prune(self, now: float) -> None:
        while self._minute and now - self._minute[0] >= 60:
            self._minute.popleft()
        while self._day and now - self._day[0] >= 86400:
            self._day.popleft()

    def try_acquire(self) -> bool:
        with self._lock:
            now = self._clock()
            self._prune(now)
            if now < self._blocked_until or len(self._minute) >= self.per_minute or len(self._day) >= self.per_day:
                return False
            self._minute.append(now)
            self._day.append(now)
            return True

    def block_for(self, seconds: float) -> None:
        """The server said 429: stop sending until the pause is over, whatever our own counters think."""
        with self._lock:
            self._blocked_until = max(self._blocked_until, self._clock() + max(1.0, min(float(seconds), 86400.0)))

    def snapshot(self) -> Dict[str, Any]:
        with self._lock:
            now = self._clock()
            self._prune(now)
            return {"used_last_minute": len(self._minute), "used_last_24h": len(self._day), "per_minute": self.per_minute,
                    "per_day": self.per_day, "paused_for_seconds": max(0, int(self._blocked_until - now))}


class TTLCache:
    def __init__(self, ttl: float, clock: Callable[[], float] = time.time, max_items: int = 2000):
        self.ttl, self._clock, self._max = ttl, clock, max_items
        self._data: Dict[Any, Tuple[float, Dict[str, Any]]] = {}
        self._lock = threading.Lock()

    def get(self, key):
        with self._lock:
            hit = self._data.get(key)
            if not hit:
                return None
            if hit[0] <= self._clock():
                del self._data[key]
                return None
            return dict(hit[1])

    def set(self, key, value: Dict[str, Any], ttl: Optional[float] = None) -> None:
        with self._lock:
            if len(self._data) >= self._max:
                self._data.pop(min(self._data, key=lambda k: self._data[k][0]))
            self._data[key] = (self._clock() + (self.ttl if ttl is None else ttl), dict(value))

    def __len__(self) -> int:
        with self._lock:
            return len(self._data)


# ---- the client ------------------------------------------------------------------------------------------------------
class VirusTotalClient:
    FAILURES_BEFORE_PAUSE = 3
    PAUSE_SECONDS = 60
    NOT_FOUND_TTL = 3600

    def __init__(self, api_key: str, *, timeout: float = 10.0, malicious_threshold: int = 3,
                 per_minute: int = 4, per_day: int = 500, cache_ttl: float = 86400,
                 transport: Optional[httpx.BaseTransport] = None, clock: Callable[[], float] = time.time):
        key = (api_key or "").strip()
        if not key:
            raise ValueError("A VirusTotal API key is required.")
        self._headers = {"x-apikey": key, "accept": "application/json"}
        self.malicious_threshold = max(1, int(malicious_threshold))
        self._clock = clock
        self.limiter = QuotaLimiter(per_minute, per_day, clock)
        self.cache = TTLCache(cache_ttl, clock)
        self._http = httpx.Client(base_url=BASE_URL, timeout=httpx.Timeout(timeout, connect=min(5.0, timeout)),
                                  transport=transport, follow_redirects=False)
        self._failures = 0
        self._paused_until = 0.0
        self._auth_failed = False
        self._lock = threading.Lock()

    def __repr__(self) -> str:  # never show the key
        return "VirusTotalClient(api_key=***)"

    def close(self) -> None:
        self._http.close()

    # -- public ---------------------------------------------------------------------------------------------------
    def lookup(self, ioc_type: str, value: Any, *, allow_request: bool = True) -> Dict[str, Any]:
        """Returns the reputation fields for one indicator. Never raises for expected failures, never sleeps."""
        try:
            collection, normalized = prepare_ioc(ioc_type, value)
        except Ineligible as skip:
            return self._outcome(skip.status, request_made=False)

        cache_key = (collection, normalized)
        cached = self.cache.get(cache_key)
        if cached is not None:
            cached["cached"] = True
            cached["request_made"] = False
            return cached

        if self._auth_failed:
            return self._outcome("auth_error", request_made=False)
        if self._clock() < self._paused_until:
            return self._outcome("circuit_open", request_made=False)
        if not allow_request:
            return self._outcome("budget_exceeded", request_made=False)
        if not self.limiter.try_acquire():
            return self._outcome("rate_limited", request_made=False)

        path = f"/{collection}/{quote(normalized, safe=':')}"
        try:
            response = self._http.get(path, headers=self._headers)
        except httpx.TimeoutException:
            return self._failure("timeout")
        except httpx.HTTPError:
            return self._failure("error")
        except Exception:  # noqa: BLE001 - nothing from a lookup may break the caller
            return self._failure("error")
        return self._handle(response, collection, normalized, cache_key)

    # -- response handling ----------------------------------------------------------------------------------------
    def _handle(self, response: httpx.Response, collection: str, value: str, cache_key) -> Dict[str, Any]:
        code = response.status_code
        if code == 200:
            try:
                result = self._map(response.json(), collection, value)
            except (ValueError, KeyError, TypeError, AttributeError):
                return self._failure("error")
            self._success()
            self.cache.set(cache_key, result)
            return {**result, "cached": False, "request_made": True}
        if code == 404:
            self._success()
            result = self._outcome("not_found", request_made=True, reference=reference_url(collection, value))
            self.cache.set(cache_key, result, ttl=self.NOT_FOUND_TTL)
            return result
        if code in (401, 403):
            # A rejected key will keep being rejected: stop sending until the app is restarted with a new key.
            self._auth_failed = True
            logger.warning("VirusTotal rejected the configured API key (HTTP %s); lookups are disabled until restart.", code)
            return self._outcome("auth_error", request_made=True)
        if code == 429:
            seconds = self._retry_after(response)
            self.limiter.block_for(seconds)
            logger.warning("VirusTotal quota reached (HTTP 429); pausing lookups for %s seconds.", int(seconds))
            return self._outcome("rate_limited", request_made=True)
        return self._failure("error")   # 5xx and any other unexpected status

    def _retry_after(self, response: httpx.Response) -> float:
        header = response.headers.get("retry-after", "")
        if header.strip().isdigit():
            return float(header.strip())
        try:
            error = response.json().get("error", {})
            if error.get("code") == "QuotaExceededError" and re.search(r"\bdaily\b|\bday\b", str(error.get("message", "")), re.I):
                now = datetime.fromtimestamp(self._clock(), timezone.utc)
                midnight = now.replace(hour=0, minute=0, second=0, microsecond=0).timestamp() + 86400
                return midnight - now.timestamp()
        except (ValueError, AttributeError, TypeError):
            pass
        return 60.0

    def _map(self, payload: Dict[str, Any], collection: str, value: str) -> Dict[str, Any]:
        attrs = payload["data"]["attributes"]
        stats = attrs.get("last_analysis_stats") or {}
        counts = {k: int(stats.get(k, 0)) for k in ("malicious", "suspicious", "harmless", "undetected")}
        if any(n < 0 for n in counts.values()):
            raise ValueError("negative count")
        total = sum(counts.values())
        flagged = counts["malicious"] + counts["suspicious"]
        if total == 0:
            reputation, confidence = "UNKNOWN", 0.0
            note = "VirusTotal has no analysis results for this indicator."
        elif counts["malicious"] >= self.malicious_threshold:
            reputation, confidence = "MALICIOUS", round(min(0.99, flagged / total), 2)
            note = f"{counts['malicious']} of {total} engines flagged it as malicious"
        elif flagged >= 1:
            reputation, confidence = "SUSPICIOUS", round(min(0.99, flagged / total), 2)
            note = f"{counts['malicious']} malicious and {counts['suspicious']} suspicious of {total} engines (below the malicious threshold of {self.malicious_threshold})"
        else:
            reputation, confidence = "CLEAN", 0.5
            note = f"0 of {total} engines flagged it. This is not proof that it is safe"
        analysed = attrs.get("last_analysis_date")
        analysed_text = ""
        if isinstance(analysed, int) and analysed > 0:
            analysed_text = datetime.fromtimestamp(analysed, timezone.utc).strftime("%Y-%m-%d")
        detected_by = []
        for engine, verdict in (attrs.get("last_analysis_results") or {}).items():
            if isinstance(verdict, dict) and verdict.get("category") == "malicious" and len(detected_by) < MAX_DETECTED_BY:
                detected_by.append("".join(ch for ch in str(engine) if ch.isprintable())[:40])
        evidence = f"{note} (VirusTotal{', analysed ' + analysed_text if analysed_text else ''})."
        return {
            "reputation": reputation, "confidence": confidence, "evidence": evidence, "provider": PROVIDER,
            "lookup_status": "completed", "detections": {**counts, "total": total}, "detected_by": sorted(detected_by),
            "retrieved_at": self._now(), "reference_url": reference_url(collection, value),
        }

    # -- helpers --------------------------------------------------------------------------------------------------
    def _now(self) -> str:
        return datetime.fromtimestamp(self._clock(), timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    def _success(self) -> None:
        with self._lock:
            self._failures = 0

    def _failure(self, status: str) -> Dict[str, Any]:
        with self._lock:
            self._failures += 1
            if self._failures >= self.FAILURES_BEFORE_PAUSE:
                self._paused_until = self._clock() + self.PAUSE_SECONDS
                self._failures = 0
                logger.warning("VirusTotal failed repeatedly; pausing lookups for %s seconds.", self.PAUSE_SECONDS)
        return self._outcome(status, request_made=True)

    def _outcome(self, status: str, *, request_made: bool, reference: Optional[str] = None) -> Dict[str, Any]:
        """A result for an indicator that was not (or not successfully) looked up. Reputation is UNKNOWN = not checked."""
        out = {
            "reputation": "UNKNOWN", "confidence": 0.0, "evidence": STATUS_TEXT[status],
            "provider": PROVIDER if request_made else "none", "lookup_status": status,
            "detections": None, "detected_by": [], "retrieved_at": self._now() if request_made else None,
            "reference_url": reference, "cached": False, "request_made": request_made,
        }
        return out
