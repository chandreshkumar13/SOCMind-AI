from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

from app.agents.correlation.correlation_agent import parse_timestamp

LOG_MARGIN = timedelta(minutes=30)
FLAGGED_REPUTATIONS = ("MALICIOUS", "SUSPICIOUS")

# (technique id, technique name, keywords, statement). Keyword rules give INDICATIVE hypotheses only.
HYPOTHESIS_RULES = [
    ("T1059.001", "PowerShell", ["powershell"], "PowerShell was used; it may have executed attacker-controlled commands."),
    ("T1027", "Obfuscated Files or Information", ["encodedcommand", "base64"], "A command appears to be encoded, which can be used to hide its purpose."),
    ("T1218.011", "System Binary Proxy Execution: Rundll32", ["rundll32"], "rundll32 was used to run a DLL, a technique that can bypass simple allow-lists."),
    ("T1071", "Application Layer Protocol", ["c2", "command & control", "command and control", "beacon"], "Network activity is consistent with command-and-control communication."),
    ("T1003.001", "OS Credential Dumping: LSASS Memory", ["minidump", "comsvcs", "lsass.dmp", "memory dump", "credential dump"], "LSASS memory access suggests an attempt to dump credentials."),
    ("T1110", "Brute Force", ["brute force", "failed password", "failed ssh", "failed login", "password spray"], "Repeated failed authentication suggests a brute-force attempt."),
    ("T1558.003", "Steal or Forge Kerberos Tickets: Kerberoasting", ["kerberoast", "rc4_hmac", "rc4"], "Service-ticket requests with weak encryption suggest Kerberoasting."),
    ("T1547.001", "Registry Run Keys / Startup Folder", ["currentversion\\run", "reg.exe add"], "A Run-key registry change suggests an attempt to persist across reboots."),
    ("T1486", "Data Encrypted for Impact", ["ransomware", "encryptor", "bulk file renam"], "Bulk file changes are consistent with ransomware encryption."),
    ("T1071.004", "Application Layer Protocol: DNS", ["dns tunnel", "tunneling", "dns-query"], "Abnormal DNS payloads suggest data exfiltration or tunneling."),
    ("T1078", "Valid Accounts", ["after-hours", "domain admin login", "unusual"], "A privileged account was used in an unusual way; credentials may be compromised."),
    ("T1098", "Account Manipulation", ["iam", "attach-user-policy", "policy attachment"], "A permission change on an account suggests privilege manipulation."),
]


def _utc(value: Any) -> Optional[str]:
    """Normalised UTC timestamp string (the same format for every event) or None when unknown."""
    dt = parse_timestamp(value)
    return dt.isoformat() + "Z" if dt else None


def _enrichment_iocs(alert: Dict[str, Any]) -> List[Dict[str, Any]]:
    """The stored enrichment IOCs of an alert (enrichment_result['iocs']), or [] when not enriched."""
    enr = (alert.get("normalized_data") or {}).get("enrichment") or {}
    iocs = enr.get("iocs")
    return iocs if isinstance(iocs, list) else []


class InvestigationAgent:
    """
    Builds an investigation timeline and findings for an incident from stored alerts (with their
    triage and enrichment results), the correlation evidence and an authorized log source.
    Every finding is labelled so uncertain information is never shown as fact:
      verified   - literally present in a stored alert, triage result, correlation record or log record
      mock_intel - reported by the LOCAL MOCK intelligence tool (unverified; never confirmed intelligence)
      hypothesis - an inference from keyword rules; needs analyst confirmation (never 'high' confidence)
    Command lines are only read as text; nothing is executed. Nothing is invented: when data is
    missing the output says so (see `limitations`).
    """

    agent_name = "Investigation Agent"

    def investigate(self, incident: Dict[str, Any], alerts: List[Dict[str, Any]], logs: List[Dict[str, Any]]) -> Dict[str, Any]:
        alerts = [a for a in (alerts or []) if a.get("id")]
        logs = logs or []
        stamps = [parse_timestamp(a.get("timestamp")) for a in alerts]
        valid = [s for s in stamps if s]
        first, last = (min(valid), max(valid)) if valid else (None, None)
        hosts = sorted({a["host"] for a in alerts if a.get("host")})
        users = sorted({a["username"] for a in alerts if a.get("username")})
        field_ips = {a[f] for a in alerts for f in ("source_ip", "destination_ip") if a.get(f)}
        hashes = {a["file_hash"] for a in alerts if a.get("file_hash")}
        domains, ioc_ips = set(), set()
        for a in alerts:
            for ioc in _enrichment_iocs(a):
                if ioc.get("type") == "DOMAIN":
                    domains.add(ioc.get("value"))
                elif ioc.get("type") == "IP":
                    ioc_ips.add(ioc.get("value"))
                elif str(ioc.get("type", "")).startswith(("MD5", "SHA")):
                    hashes.add(ioc.get("value"))
        ips = sorted(field_ips | ioc_ips)
        domain_note = ("Domains are extracted heuristically from alert text and may include false positives such as parts of file paths."
                       if domains else None)

        relevant_logs = self._relevant_logs(logs, hosts, ips, first, last)
        timeline = self._timeline(alerts, relevant_logs)
        findings: List[Dict[str, Any]] = []
        limitations: List[str] = []

        # ---- verified facts
        findings.append(self._finding("verified", f"{len(alerts)} alert(s) are linked to this incident on host(s) {', '.join(hosts) or 'unknown'}"
                                      + (f" between {first.isoformat()}Z and {last.isoformat()}Z." if first else "."),
                                      basis=[f"alert:{a['id']}" for a in alerts]))
        for reason in ((incident.get("correlation") or {}).get("reasons") or []):
            findings.append(self._finding("verified", f"Correlation evidence: {reason}.", basis=[f"alert:{a['id']}" for a in alerts]))
        triaged = [(a, (a.get("normalized_data") or {}).get("triage")) for a in alerts]
        triaged = [(a, t) for a, t in triaged if isinstance(t, dict) and isinstance(t.get("suspicion_score"), (int, float))]
        triage_summary = None
        if triaged:
            top_alert, top_triage = max(triaged, key=lambda p: (p[1]["suspicion_score"], str(p[0]["id"])))
            triage_summary = {"alerts_triaged": len(triaged), "max_suspicion_score": top_triage["suspicion_score"],
                              "highest_priority": top_triage.get("priority"), "top_alert": top_alert["id"]}
            findings.append(self._finding("verified", f"Deterministic triage rated alert {top_alert['id']} {top_triage['suspicion_score']}/100 "
                                          f"(priority {top_triage.get('priority')}); {len(triaged)} of {len(alerts)} alert(s) are triaged.",
                                          basis=[f"alert:{top_alert['id']}", "triage"]))
        if len(triaged) < len(alerts):
            limitations.append(f"{len(alerts) - len(triaged)} alert(s) have no triage result.")
        for field in ("destination_ip", "source_ip"):
            for value in sorted({a[field] for a in alerts if a.get(field)}):
                ids = [a["id"] for a in alerts if a.get(field) == value]
                if len(ids) >= 2:
                    findings.append(self._finding("verified", f"{'Destination IP' if field == 'destination_ip' else 'Source IP'} {value} appears in {len(ids)} alerts: {', '.join(ids)}.",
                                                  basis=[f"alert:{i}" for i in ids]))
        corroborated = []
        for lg in relevant_logs:
            for ip in ips:
                if ip in str(lg.get("message", "")):
                    corroborated.append(lg)
                    findings.append(self._finding("verified", f"Log {lg.get('log_id')} ({lg.get('log_type')}) mentions {ip}: {str(lg.get('message'))[:160]}",
                                                  basis=[f"log:{lg.get('log_id')}"]))
                    break
        if not relevant_logs:
            findings.append(self._finding("verified", "No matching log records were found in the available log source; the timeline is built from alerts only.", basis=[]))
            limitations.append("No log records corroborate the alerts.")

        # ---- mock intelligence (unverified)
        mock_hits = []
        enriched = 0
        for a in alerts:
            iocs = _enrichment_iocs(a)
            if (a.get("normalized_data") or {}).get("enrichment"):
                enriched += 1
            for ioc in iocs:
                if ioc.get("reputation") in FLAGGED_REPUTATIONS:
                    mock_hits.append((a["id"], ioc))
        if enriched < len(alerts):
            limitations.append(f"{len(alerts) - enriched} alert(s) have no enrichment result.")
        if enriched:
            limitations.append("Threat intelligence is a local mock; reputations (including CLEAN) are not verified.")
        seen = set()
        for aid, ioc in mock_hits:
            key = (ioc.get("type"), ioc.get("value"), ioc.get("reputation"))
            if key in seen:
                continue
            seen.add(key)
            findings.append(self._finding("mock_intel", f"MOCK intelligence flags {ioc.get('type')} {ioc.get('value')} as {str(ioc.get('reputation')).lower()} "
                                          f"(provider {ioc.get('provider')}). Unverified.",
                                          basis=[f"alert:{aid}", f"intel:{ioc.get('provider')}"], reputation=ioc.get("reputation"),
                                          confidence=ioc.get("confidence")))

        # ---- hypotheses
        hypotheses = self._hypotheses(alerts, relevant_logs)
        findings.extend(hypotheses)

        strength = "strong" if (len(alerts) >= 3 and corroborated) else ("moderate" if len(alerts) >= 2 else "weak")
        if domain_note:
            limitations.append(domain_note)
        if not alerts:
            limitations.append("The incident has no readable alerts.")
        if len(valid) < len(alerts):
            limitations.append(f"{len(alerts) - len(valid)} alert(s) have no valid timestamp and appear last in the timeline.")
        summary = self._summary(incident, alerts, hosts, first, last, relevant_logs, mock_hits, hypotheses, strength, triage_summary)
        return {
            "agent": self.agent_name, "status": "completed",
            "entities": {"hosts": hosts, "users": users, "ips": ips, "hashes": sorted(h for h in hashes if h),
                         "domains": sorted(d for d in domains if d)},
            "time_span": {"first": first.isoformat() + "Z" if first else None, "last": last.isoformat() + "Z" if last else None, "timezone": "UTC"},
            "log_records_used": len(relevant_logs), "evidence_strength": strength,
            "triage": triage_summary,
            "correlation": incident.get("correlation"),
            "timeline": timeline, "findings": findings,
            "counts": {"verified": sum(f["type"] == "verified" for f in findings), "mock_intel": sum(f["type"] == "mock_intel" for f in findings),
                       "hypothesis": len(hypotheses)},
            "limitations": limitations, "summary": summary,
            "note": "Hypotheses are indicative inferences from keyword rules and require analyst confirmation.",
        }

    @staticmethod
    def _finding(kind: str, statement: str, basis: List[str], **extra) -> Dict[str, Any]:
        return {"type": kind, "statement": statement, "basis": basis, **extra}

    @staticmethod
    def _relevant_logs(logs, hosts, ips, first: Optional[datetime], last: Optional[datetime]):
        lower_hosts = {h.lower() for h in hosts}
        out = []
        for lg in logs:
            ts = parse_timestamp(lg.get("timestamp"))
            if first and last and ts and not (first - LOG_MARGIN <= ts <= last + LOG_MARGIN):
                continue
            host_match = str(lg.get("host") or "").lower() in lower_hosts
            ip_match = any(ip in str(lg.get("message", "")) for ip in ips)
            if host_match or ip_match:
                out.append(lg)
        return sorted(out, key=lambda lg: (parse_timestamp(lg.get("timestamp")) or datetime.min, str(lg.get("log_id"))))

    @staticmethod
    def _timeline(alerts, logs):
        events = []
        for a in alerts:
            events.append({"time": _utc(a.get("timestamp")), "type": "alert", "ref": a["id"], "host": a.get("host"), "user": a.get("username"),
                           "severity": a.get("severity"), "description": a.get("alert_title"), "evidence_type": "verified"})
        for lg in logs:
            events.append({"time": _utc(lg.get("timestamp")), "type": "log", "ref": lg.get("log_id"), "host": lg.get("host"), "user": lg.get("user"),
                           "severity": None, "description": str(lg.get("message"))[:300], "evidence_type": "verified"})
        # events with an unknown time go last; their time stays None rather than being invented
        events.sort(key=lambda e: (e["time"] is None, e["time"] or "", e["type"], str(e["ref"])))
        return events

    @staticmethod
    def _hypotheses(alerts, logs):
        results = []
        for tid, name, words, statement in HYPOTHESIS_RULES:
            basis = []
            for a in alerts:
                text = " ".join(str(a.get(k) or "") for k in ("alert_title", "description", "command_line")).lower()
                if any(w in text for w in words):
                    basis.append(f"alert:{a['id']}")
            for lg in logs:
                if any(w in str(lg.get("message", "")).lower() for w in words):
                    basis.append(f"log:{lg.get('log_id')}")
            if basis:
                kinds = {b.split(":")[0] for b in basis}
                medium = len(set(basis)) >= 2 and (len(kinds) >= 2 or len(set(basis)) >= 3)
                results.append({"type": "hypothesis", "statement": statement, "technique": tid, "technique_name": name,
                                "confidence": "medium" if medium else "low", "basis": sorted(set(basis)),
                                "note": "Inference from keyword rules; requires analyst confirmation."})
        return results

    @staticmethod
    def _summary(incident, alerts, hosts, first, last, logs, mock_hits, hyps, strength, triage) -> str:
        parts = [f"Incident {incident.get('id', '')} groups {len(alerts)} alert(s) on {', '.join(hosts) or 'unknown host'}"]
        if first and last:
            minutes = int((last - first).total_seconds() // 60)
            parts[0] += f" over about {minutes} minute(s)"
        parts[0] += f". Evidence strength: {strength}."
        if triage:
            parts.append(f"Highest triage score {triage['max_suspicion_score']}/100 ({triage['highest_priority']}).")
        parts.append(f"{len(logs)} related log record(s) were reviewed.")
        if mock_hits:
            parts.append(f"Mock (unverified) intelligence flagged {len({(i.get('type'), i.get('value')) for _, i in mock_hits})} indicator(s).")
        if hyps:
            parts.append("Possible techniques (hypotheses, not confirmed): " + "; ".join(f"{h['technique']} {h['technique_name']} [{h['confidence']}]" for h in hyps[:6]) + ".")
        parts.append("No automated action has been taken; analyst review is required.")
        return " ".join(parts)
