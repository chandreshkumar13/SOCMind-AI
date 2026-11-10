from collections import Counter
from typing import Any, Dict

from app.agents.enrichment.enrichment_agent import DECODED_SOURCE, EnrichmentAgent
from app.tools.virustotal import RETRYABLE_STATUSES, STATUS_TEXT, VirusTotalClient


class LiveEnrichmentAgent(EnrichmentAgent):
    """EnrichmentAgent that looks indicators up on VirusTotal instead of the local mock.

    Only `_lookup_ioc` and the result summary differ; IOC extraction, de-duplication and the result contract
    (agent, status, alert_id, total_iocs_extracted, summary, iocs[]) are inherited unchanged. Extra keys are
    additive: per IOC `lookup_status`, `detections`, `detected_by`, `retrieved_at`, `reference_url`, `cached`;
    per result `lookup_summary` and `incomplete`.

    A single call spends at most `max_lookups` network requests. Indicators answered from the cache, and
    indicators that must not leave the network, cost nothing. What cannot be looked up now is reported as
    UNKNOWN with a retryable `lookup_status`, and the result is marked `incomplete` so a later run can finish it.
    """

    def __init__(self, client: VirusTotalClient, max_lookups: int = 5, lookup_decoded: bool = False):
        super().__init__(mock_mode=False)
        self.client = client
        self.max_lookups = max(0, int(max_lookups))
        # Indicators decoded from encoded command lines are sent only when the operator has turned this on
        self.lookup_decoded = bool(lookup_decoded)
        self._reset()

    def _reset(self) -> None:
        self._budget = self.max_lookups
        self._requests = 0
        self._statuses: Counter = Counter()
        self._cached = 0
        self._decoded_not_sent = 0

    def enrich_alert(self, alert_data: Dict[str, Any]) -> Dict[str, Any]:
        self._reset()
        result = super().enrich_alert(alert_data)
        retryable = sum(n for status, n in self._statuses.items() if status in RETRYABLE_STATUSES)
        skipped = sum(n for status, n in self._statuses.items() if status.startswith("skipped"))
        result["lookup_summary"] = {
            "requests_made": self._requests,
            "completed": self._statuses["completed"] + self._statuses["not_found"],
            "from_cache": self._cached,
            "skipped_ineligible": skipped,
            "not_looked_up_retryable": retryable,
            "rate_limited": self._statuses["rate_limited"],
            "per_alert_limit_reached": self._statuses["budget_exceeded"],
            "failed": self._statuses["timeout"] + self._statuses["error"] + self._statuses["circuit_open"],
            "auth_error": self._statuses["auth_error"],
            "decoded_not_sent": self._decoded_not_sent,
        }
        result["lookup_performed"] = (self._requests + self._cached) > 0
        result["incomplete"] = retryable > 0
        return result

    def _lookup_ioc(self, val: str, ioc_type: str, source_field: str) -> Dict[str, Any]:
        if source_field == DECODED_SOURCE and not self.lookup_decoded:
            # Decoded text is not sent to a third party unless the operator opted in. Nothing is requested, nothing is spent.
            self._decoded_not_sent += 1
            self._statuses["not_sent_decoded_disabled"] += 1
            return {"value": val, "type": ioc_type, "source": source_field, "reputation": "UNKNOWN", "confidence": 0.0,
                    "evidence": STATUS_TEXT["not_sent_decoded_disabled"], "provider": "none",
                    "lookup_status": "not_sent_decoded_disabled", "detections": None, "detected_by": [],
                    "retrieved_at": None, "reference_url": None, "cached": False}
        try:
            outcome = self.client.lookup(ioc_type, val, allow_request=self._budget > 0)
        except Exception:  # noqa: BLE001 - one indicator must never break the enrichment of an alert
            outcome = {"reputation": "UNKNOWN", "confidence": 0.0, "evidence": STATUS_TEXT["error"], "provider": "none",
                       "lookup_status": "error", "detections": None, "detected_by": [], "retrieved_at": None,
                       "reference_url": None, "cached": False, "request_made": False}
        if outcome.pop("request_made", False):
            self._budget -= 1
            self._requests += 1
        if outcome.get("cached"):
            self._cached += 1
        self._statuses[outcome.get("lookup_status", "error")] += 1
        return {"value": val, "type": ioc_type, "source": source_field, **outcome}
