"""Chooses which threat-intelligence source enrichment uses.

Order of precedence
1. THREAT_INTEL_MOCK_MODE=false  -> "unavailable": indicators are extracted, nothing is looked up (unchanged behaviour).
2. THREAT_INTEL_PROVIDER=virustotal and a non-empty VIRUSTOTAL_API_KEY -> "virustotal" (live, opt-in).
3. THREAT_INTEL_PROVIDER=virustotal but no key -> "mock", with `reason` explaining the fallback (never silent).
4. anything else, including the default "mock" and unknown values -> "mock".
"""
import hashlib
import logging
import threading
from dataclasses import dataclass
from typing import Optional

from app.core.config import settings
from app.tools.virustotal import VirusTotalClient

logger = logging.getLogger("socmind.intel")


@dataclass(frozen=True)
class ProviderChoice:
    requested: str            # what the configuration asked for
    active: str               # "mock" | "virustotal" | "unavailable"
    reason: Optional[str] = None   # why the active provider differs from the request, if it does


def _key() -> str:
    secret = settings.VIRUSTOTAL_API_KEY
    return secret.get_secret_value().strip() if secret is not None else ""


def api_key_configured() -> bool:
    return bool(_key())


def resolve_provider() -> ProviderChoice:
    requested = str(settings.THREAT_INTEL_PROVIDER or "mock").strip().lower()[:40] or "mock"
    if not settings.THREAT_INTEL_MOCK_MODE:
        return ProviderChoice(requested, "unavailable", "THREAT_INTEL_MOCK_MODE is false: no lookups are performed.")
    if requested == "virustotal":
        if api_key_configured():
            return ProviderChoice(requested, "virustotal")
        return ProviderChoice(requested, "mock", "VirusTotal was requested but VIRUSTOTAL_API_KEY is not configured; using the local mock provider.")
    if requested != "mock":
        return ProviderChoice(requested, "mock", f"Unknown THREAT_INTEL_PROVIDER '{requested}'; using the local mock provider.")
    return ProviderChoice(requested, "mock")


# One client per process so the quota counters, cache and circuit breaker are shared by every request.
_client: Optional[VirusTotalClient] = None
_client_fingerprint = None
_client_lock = threading.Lock()


def _fingerprint():
    return (hashlib.sha256(_key().encode()).hexdigest(), settings.VIRUSTOTAL_TIMEOUT_SECONDS, settings.VIRUSTOTAL_MALICIOUS_THRESHOLD,
            settings.VIRUSTOTAL_REQUESTS_PER_MINUTE, settings.VIRUSTOTAL_REQUESTS_PER_DAY, settings.VIRUSTOTAL_CACHE_TTL_SECONDS)


def get_client() -> VirusTotalClient:
    """The shared client, rebuilt only when the relevant settings change."""
    global _client, _client_fingerprint
    with _client_lock:
        fingerprint = _fingerprint()
        if _client is None or fingerprint != _client_fingerprint:
            if _client is not None:
                _client.close()
            _client = VirusTotalClient(
                _key(), timeout=settings.VIRUSTOTAL_TIMEOUT_SECONDS, malicious_threshold=settings.VIRUSTOTAL_MALICIOUS_THRESHOLD,
                per_minute=settings.VIRUSTOTAL_REQUESTS_PER_MINUTE, per_day=settings.VIRUSTOTAL_REQUESTS_PER_DAY,
                cache_ttl=settings.VIRUSTOTAL_CACHE_TTL_SECONDS)
            _client_fingerprint = fingerprint
        return _client


def reset_client() -> None:
    """Forget the shared client (tests; also useful after changing settings at runtime)."""
    global _client, _client_fingerprint
    with _client_lock:
        if _client is not None:
            _client.close()
        _client, _client_fingerprint = None, None


def quota_snapshot() -> Optional[dict]:
    """Quota usage of the live client, or None when live lookups are not active. Contains no secrets."""
    if resolve_provider().active != "virustotal":
        return None
    return get_client().limiter.snapshot()
