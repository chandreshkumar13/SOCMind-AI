import ipaddress
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

SEVERITY_ORDER = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
# Entities strong enough to link two alerts on their own
STRONG_FIELDS = ("host", "source_ip", "destination_ip", "file_hash")
# Supporting entity: reported as evidence but never links alerts by itself (usernames like "root" are shared by many)
WEAK_FIELDS = ("username",)
IP_FIELDS = ("source_ip", "destination_ip")


def parse_timestamp(value: Any) -> Optional[datetime]:
    """Parses a timestamp into a naive UTC datetime, or None when it is missing or malformed.

    Timezone-aware values are converted to UTC first so alerts reported with different offsets
    (e.g. '+05:30' and 'Z') are compared on the same clock. Naive values are assumed to be UTC.
    """
    if isinstance(value, datetime):
        dt = value
    elif isinstance(value, str) and value.strip():
        try:
            dt = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
        except ValueError:
            return None
    else:
        return None
    if dt.tzinfo is not None:
        dt = dt.astimezone(timezone.utc).replace(tzinfo=None)
    return dt


# Kept under its original private name for existing importers
_parse_ts = parse_timestamp


def _norm(value: Any, field: str = "") -> Optional[str]:
    """Comparison key for an entity: trimmed, case-insensitive, IPs in canonical form."""
    if value in (None, ""):
        return None
    text = str(value).strip().lower()
    if not text:
        return None
    if field in IP_FIELDS:
        try:
            return ipaddress.ip_address(text).compressed
        except ValueError:
            pass
    return text


def _severity(value: Any) -> str:
    sev = str(value or "").strip().upper()
    return sev if sev in SEVERITY_ORDER else "MEDIUM"


class CorrelationAgent:
    """
    Groups alerts into incident candidates. Two alerts are linked when they share at least one
    STRONG entity (host, source IP, destination IP, file hash) and occurred within the time window.
    Linking is transitive. Groups smaller than `min_alerts` are not incidents (insufficient evidence).

    Deterministic: the same input always yields the same groups, ordering and reasons.
    Alerts that are CLOSED, have no id, or have no valid timestamp are never linked (a time window
    cannot be applied to them); `last_skipped` lists the ids of those so callers can report them.
    """

    agent_name = "Correlation Agent"

    def __init__(self):
        self.last_skipped: Dict[str, List[str]] = {"no_valid_timestamp": [], "closed": [], "no_id": []}

    def correlate_alerts(self, alerts: List[Dict[str, Any]], window_hours: int = 24, min_alerts: int = 2) -> List[Dict[str, Any]]:
        self.last_skipped = {"no_valid_timestamp": [], "closed": [], "no_id": []}
        usable: List[Dict[str, Any]] = []
        stamps: List[datetime] = []
        for a in alerts or []:
            if not a.get("id"):
                self.last_skipped["no_id"].append("?")
            elif str(a.get("status") or "").upper() == "CLOSED":
                self.last_skipped["closed"].append(str(a["id"]))
            elif parse_timestamp(a.get("timestamp")) is None:
                self.last_skipped["no_valid_timestamp"].append(str(a["id"]))
            else:
                usable.append(a)
                stamps.append(parse_timestamp(a.get("timestamp")))

        n = len(usable)
        parent = list(range(n))

        def find(i):
            while parent[i] != i:
                parent[i] = parent[parent[i]]
                i = parent[i]
            return i

        window = timedelta(hours=window_hours)
        keys = [{f: _norm(a.get(f), f) for f in STRONG_FIELDS} for a in usable]
        for i in range(n):
            for j in range(i + 1, n):
                if abs(stamps[i] - stamps[j]) > window:
                    continue
                if any(keys[i][f] and keys[i][f] == keys[j][f] for f in STRONG_FIELDS):
                    parent[find(i)] = find(j)

        components: Dict[int, List[int]] = {}
        for i in range(n):
            components.setdefault(find(i), []).append(i)

        groups = []
        for members in components.values():
            if len(members) < min_alerts:
                continue
            members.sort(key=lambda k: (stamps[k], str(usable[k]["id"])))
            groups.append(self._describe_group([usable[k] for k in members], [stamps[k] for k in members]))
        groups.sort(key=lambda g: (-SEVERITY_ORDER[g["severity"]], g["first_seen"] or "", g["alert_ids"]))
        return groups

    def _describe_group(self, members: List[Dict[str, Any]], stamps: List[datetime]) -> Dict[str, Any]:
        shared: Dict[str, List[str]] = {}
        strong_hits = 0
        for field in STRONG_FIELDS + WEAK_FIELDS:
            counts: Dict[str, int] = {}
            original: Dict[str, str] = {}   # keep the original capitalisation for display
            for a in members:
                v = _norm(a.get(field), field)
                if v:
                    counts[v] = counts.get(v, 0) + 1
                    original.setdefault(v, str(a.get(field)).strip())
            vals = sorted(original[v] for v, c in counts.items() if c >= 2)
            if vals:
                shared[field] = vals
                if field in STRONG_FIELDS:
                    strong_hits += 1
        top = max(members, key=lambda a: SEVERITY_ORDER[_severity(a.get("severity"))])
        reasons = [f"{len(members)} alerts share {f.replace('_', ' ')} {', '.join(v)}" for f, v in shared.items()]
        return {
            "alert_ids": [str(a["id"]) for a in members],
            "alert_count": len(members),
            "severity": _severity(top.get("severity")),
            "top_alert_title": top.get("alert_title"),
            "primary_host": (shared.get("host") or [top.get("host")])[0],
            "shared_entities": shared,
            "reasons": reasons,
            "confidence": "high" if strong_hits >= 2 else "medium",
            "first_seen": stamps[0].isoformat(),
            "last_seen": stamps[-1].isoformat(),
        }
