from typing import Any, Dict, List, Optional

IMPACT_ORDER = {"NONE": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3}
MOCK_INTEL_CAVEAT = "The local threat intelligence is a mock and unverified; confirm the indicator with an authoritative source first."


def _text(a: Dict[str, Any]) -> str:
    return " ".join(str(a.get(k) or "") for k in ("alert_title", "description", "command_line")).lower()


def _has(alert: Dict[str, Any], words: List[str]) -> bool:
    t = _text(alert)
    return any(w in t for w in words)


def _flagged_iocs(alerts: List[Dict[str, Any]], ioc_type: str) -> List[str]:
    """Values of enrichment IOCs of one type (e.g. 'IP') that the MOCK intelligence rated MALICIOUS."""
    values = set()
    for a in alerts:
        for ioc in ((a.get("normalized_data") or {}).get("enrichment") or {}).get("iocs") or []:
            if ioc.get("type") == ioc_type and ioc.get("reputation") == "MALICIOUS" and ioc.get("value"):
                values.add(ioc["value"])
    return sorted(values)


class ResponseAgent:
    """
    Proposes response actions for an incident. NOTHING is executed: every recommendation is
    flagged requires_approval=True, executed=False and starts as PENDING. If the evidence is weak,
    the agent recommends gathering more evidence instead of containment.

    Each recommendation carries its justification, expected benefit, operational impact, the risk of
    acting wrongly, the approvals required, preconditions, validation steps and rollback guidance.
    Mock intelligence is only ever cited as unverified supporting context.
    """

    agent_name = "Response Agent"

    def recommend(self, incident: Dict[str, Any], alerts: List[Dict[str, Any]], investigation: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        alerts = [a for a in (alerts or []) if a.get("id")]
        strength = (investigation or {}).get("evidence_strength") or ("weak" if len(alerts) < 2 else "moderate")
        hypotheses = [f for f in (investigation or {}).get("findings", []) if f.get("type") == "hypothesis"]
        recs: List[Dict[str, Any]] = []
        hosts = sorted({a["host"] for a in alerts if a.get("host")})
        severity = str(incident.get("severity", "")).upper()

        def match(words):
            return [a for a in alerts if _has(a, words)]

        def add(priority, category, action, target, why, matched, impact, *, benefit, operational, risk, rollback,
                approvals, preconditions, validation, reversible=True):
            evidence = sorted({f"alert:{a['id']}" for a in matched})
            techniques = sorted({h["technique"] for h in hypotheses if set(h.get("basis", [])) & set(evidence)})
            recs.append({"priority": priority, "category": category, "action": action, "target": target, "justification": why,
                         "supporting_evidence": evidence, "related_techniques": techniques,
                         "expected_benefit": benefit, "impact": impact, "operational_impact": operational,
                         "risk_if_wrong": risk, "reversible": reversible, "rollback": rollback,
                         "required_approvals": approvals, "preconditions": preconditions, "validation_steps": validation})

        if strength != "weak":
            m = match(["ransomware", "encryptor", "bulk file renam"])
            if m:
                h = sorted({a["host"] for a in m if a.get("host")}) or hosts
                add(1, "isolation", f"Isolate host(s) {', '.join(h)} from the network", ", ".join(h),
                    "Alerts are consistent with ransomware activity; isolation limits further file encryption.", m, "HIGH",
                    benefit="Stops lateral spread and further file encryption.",
                    operational="The host(s) lose all network access; users on them cannot work and hosted services go offline.",
                    risk="Isolating a healthy or business-critical host causes an avoidable outage.",
                    rollback="Remove the host(s) from the isolation group in the EDR/network console once cleared.",
                    approvals=["SOC Lead", "IT Operations owner of the host"],
                    preconditions=["Confirm the alerts are not a known backup or encryption job.", "Preserve volatile evidence first if possible.",
                                   "Confirm the host is not a critical production service, or that the business owner accepts the outage."],
                    validation=["Confirm the host no longer reaches the network.", "Confirm file changes stop on shares the host could reach."])
            m = match(["lsass", "minidump", "comsvcs", "kerberoast", "rc4", "domain admin login", "after-hours", "iam", "policy attachment"])
            if m:
                users = sorted({a["username"] for a in m if a.get("username")})
                add(2, "credentials", f"Reset credentials and revoke active sessions for {', '.join(users) or 'affected accounts'}", ", ".join(users),
                    "Credential theft or abuse of privileged or cloud accounts is suspected.", m, "MEDIUM",
                    benefit="Invalidates credentials an attacker may have stolen, cutting off access.",
                    operational="The account owners are signed out and must re-authenticate; service accounts may break dependent jobs.",
                    risk="Resetting a service account without coordination can interrupt production workloads.",
                    rollback="Credentials cannot be restored; re-issue access through the normal identity process.",
                    approvals=["Identity/IAM owner", "SOC Lead"],
                    preconditions=["Identify the services that use each account.", "Prepare the new credentials and a communication to the owners."],
                    validation=["Confirm old sessions and tokens are revoked.", "Review sign-in logs for further use of the old credentials."],
                    reversible=False)
            bad_ips = _flagged_iocs(alerts, "IP")
            m = match(["c2", "command & control", "command and control", "beacon"]) or ([a for a in alerts if a.get("destination_ip") in bad_ips] if bad_ips else [])
            if m:
                targets = bad_ips or sorted({a["destination_ip"] for a in m if a.get("destination_ip")})
                add(3, "ioc_blocking", f"Block outbound traffic to {', '.join(targets) or 'the suspicious destination'} at the perimeter firewall", ", ".join(targets),
                    "Hosts communicated with a destination flagged by command-and-control alerts or MOCK intelligence (unverified).", m, "LOW",
                    benefit="Cuts the command-and-control channel and prevents data leaving to that destination.",
                    operational="Legitimate traffic to the same address (shared hosting, CDN) would also be blocked.",
                    risk="Blocking an address that is actually legitimate disrupts business traffic; the intelligence behind it is a mock.",
                    rollback="Delete the firewall rule.",
                    approvals=["Network/Firewall owner"],
                    preconditions=[MOCK_INTEL_CAVEAT, "Check that no business service uses the destination."],
                    validation=["Confirm blocked connection attempts appear in the firewall logs.", "Confirm no business application reports failures."])
            hashes = _flagged_iocs(alerts, "SHA256") + _flagged_iocs(alerts, "SHA1") + _flagged_iocs(alerts, "MD5")
            if hashes:
                hm = [a for a in alerts if a.get("file_hash") in hashes] or alerts
                add(6, "ioc_blocking", f"Add file hash(es) {', '.join(h[:16] + '...' for h in hashes[:3])} to the endpoint blocklist and scan for other copies",
                    ", ".join(hashes[:3]), "File hash(es) were rated malicious by MOCK intelligence (unverified).", hm, "LOW",
                    benefit="Prevents the file from running again on managed endpoints and finds other copies.",
                    operational="A wrongly blocked file stops working on every endpoint.",
                    risk="The intelligence is a mock, so the file may be benign.",
                    rollback="Remove the hash from the blocklist.",
                    approvals=["Endpoint security owner"],
                    preconditions=[MOCK_INTEL_CAVEAT, "Confirm the file is not a legitimate tool."],
                    validation=["Confirm the blocklist entry is active.", "Review the scan results for other hosts."])
            domains = _flagged_iocs(alerts, "DOMAIN")
            if domains:
                add(6, "ioc_blocking", f"Block DNS resolution of {', '.join(domains[:5])} at the DNS/proxy layer", ", ".join(domains[:5]),
                    "Domain(s) were rated malicious by MOCK intelligence (unverified).", alerts, "LOW",
                    benefit="Prevents hosts from reaching attacker-controlled domains.",
                    operational="Legitimate use of the domain would be blocked.",
                    risk="The intelligence is a mock, so the domain may be legitimate.",
                    rollback="Remove the DNS/proxy block rule.",
                    approvals=["Network/Security operations owner"],
                    preconditions=[MOCK_INTEL_CAVEAT],
                    validation=["Confirm lookups for the domain are refused.", "Confirm no business application reports failures."])
            m = match(["brute force", "failed ssh", "failed password", "failed login", "password spray"])
            if m:
                src = sorted({a["destination_ip"] or a["source_ip"] for a in m if (a.get("destination_ip") or a.get("source_ip"))})
                tgt = ', '.join(sorted({a['host'] for a in m if a.get('host')}))
                add(4, "ioc_blocking", f"Rate-limit or block the remote source {', '.join(src)} and enforce lockout/MFA on {tgt}", ", ".join(src),
                    "Repeated failed authentication indicates a brute-force attempt.", m, "LOW",
                    benefit="Stops further password guessing against the target.",
                    operational="Users behind a shared address, or who mistype passwords, may be locked out.",
                    risk="Blocking a shared or internal address locks out legitimate users.",
                    rollback="Remove the rate limit/block rule and unlock the affected accounts.",
                    approvals=["Network/Firewall owner", "Identity/IAM owner"],
                    preconditions=["Confirm the source address is not an internal or partner system."],
                    validation=["Confirm failed attempts from the source stop.", "Confirm legitimate users can still sign in."])
            m = match(["currentversion\\run", "reg.exe add", "schtasks", "autorun"])
            if m:
                h = sorted({a["host"] for a in m if a.get("host")})
                add(5, "persistence_removal", f"Remove the persistence entry and run a full EDR scan on {', '.join(h)}", ", ".join(h),
                    "A startup/registry persistence mechanism was created.", m, "MEDIUM",
                    benefit="Removes the attacker's way back in after a reboot.",
                    operational="The scan consumes host resources; removing a legitimate startup entry breaks that software.",
                    risk="Deleting an entry that belongs to legitimate software disables it.",
                    rollback="Restore the saved registry key/scheduled task export.",
                    approvals=["SOC Lead", "Endpoint owner"],
                    preconditions=["Export the registry key or task definition as evidence before removing it."],
                    validation=["Confirm the entry no longer exists after a reboot.", "Confirm the scan finds no related files."])
            m = match(["dns tunnel", "tunneling", "dns-query"])
            if m:
                add(6, "dns_control", "Block DNS requests to the external resolver and review DNS logs for the host", ", ".join(sorted({a["host"] for a in m if a.get("host")})),
                    "Abnormal DNS payloads may indicate exfiltration.", m, "LOW",
                    benefit="Stops DNS being used as a data channel.",
                    operational="Name resolution through that resolver fails for the host.",
                    risk="Blocking a resolver the host legitimately needs breaks its connectivity.",
                    rollback="Remove the DNS block rule.",
                    approvals=["Network operations owner"],
                    preconditions=["Confirm the host has an approved internal resolver to fall back on."],
                    validation=["Confirm the external resolver is no longer contacted.", "Confirm normal name resolution still works."])
            m = match(["powershell", "rundll32", "encodedcommand", " -e "])
            has_risky = any(r["impact"] in ("MEDIUM", "HIGH") for r in recs)
            if hosts and (has_risky or (m and severity in ("CRITICAL", "HIGH"))):
                src = m or alerts
                h = sorted({a["host"] for a in src if a.get("host")}) or hosts
                add(7, "evidence_preservation", f"Collect a forensic triage package (memory, process list, logs) from {', '.join(h)} before containment", ", ".join(h),
                    "Preserving evidence first keeps the data needed to confirm or refute the hypotheses; containment can destroy volatile data.", src, "LOW",
                    benefit="Keeps volatile and disk evidence for confirmation, scoping and any later legal or compliance need.",
                    operational="Collection briefly increases load on the host.",
                    risk="Running collection tools on a compromised host may alert the attacker.",
                    rollback="Not applicable; collection is read-only.",
                    approvals=["SOC Lead"],
                    preconditions=["Use the approved forensic collection tooling.", "Store the package in write-once evidence storage."],
                    validation=["Confirm the package hash is recorded.", "Confirm the package can be opened by the analyst."])
        if not recs:
            reason = ("Evidence is weak (single or uncorroborated alert); containment is not justified yet."
                      if strength == "weak" else "No specific containment rule matched the incident's evidence.")
            add(9, "investigation", "Continue monitoring and collect additional evidence before any containment", ", ".join(hosts), reason, alerts, "NONE",
                benefit="Avoids disruptive action on unconfirmed evidence while the picture develops.",
                operational="None; no change is made to any system.",
                risk="Delaying action could let a real attack progress; re-check as new alerts arrive.",
                rollback="Not applicable.",
                approvals=["SOC Analyst"],
                preconditions=[],
                validation=["Re-run correlation and investigation when new alerts arrive."])

        recs.sort(key=lambda r: r["priority"])   # stable: equal priorities keep rule order
        for i, r in enumerate(recs, start=1):
            r.update({"id": f"REC-{i}", "requires_approval": True, "status": "PENDING", "executed": False})
        scores = [(a.get("normalized_data") or {}).get("triage", {}).get("suspicion_score") for a in alerts]
        scores = [s for s in scores if isinstance(s, (int, float))]
        return {
            "agent": self.agent_name, "status": "completed", "evidence_strength": strength,
            "requires_human_approval": True, "execution_mode": "simulation_only",
            "recommendations": recs, "primary_action": recs[0]["action"],
            "max_impact": max(recs, key=lambda r: IMPACT_ORDER[r["impact"]])["impact"],
            "context": {"alerts": len(alerts), "hosts": hosts, "incident_severity": severity or None,
                        "max_triage_score": max(scores) if scores else None},
            "note": "Recommendations are proposals. No action is executed by SOCMind AI; a human must approve or reject.",
        }
