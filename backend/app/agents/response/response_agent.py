import ipaddress
import re
from typing import Any, Dict, List, Optional, Set, Tuple

IMPACT_ORDER = {"NONE": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3}
MOCK_INTEL_CAVEAT = "The local threat intelligence is a mock and unverified; confirm the indicator with an authoritative source first."
LIVE_INTEL_CAVEAT = ("The reputation comes from VirusTotal and is not independently verified; open the VirusTotal report and "
                     "confirm the indicator before acting.")


def _uses_live_intel(alerts: List[Dict[str, Any]]) -> bool:
    return any((((a.get("normalized_data") or {}).get("enrichment") or {}).get("intel_mode") == "live") for a in alerts)


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


# Internal address space: RFC 1918, loopback and link-local. Any other usable address counts as external. This list is
# deliberate: ipaddress.is_private also covers the documentation ranges the synthetic sample data uses for external attackers.
_INTERNAL_NETWORKS = tuple(ipaddress.ip_network(n) for n in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "169.254.0.0/16", "::1/128", "fe80::/10", "fc00::/7"))
_IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")   # word boundaries, so a sentence-ending full stop does not hide an address
_ORIGIN_WORDS = re.compile(r"\b(from|source|attacker|origin|originating)\b", re.IGNORECASE)
_TARGET_WORDS = re.compile(r"\b(to|towards?|outbound|target|victim|against|destination|destined)\b", re.IGNORECASE)
_ROLE_WINDOW = 80   # characters before an address that are searched for the word giving its role (never past its own line)


def _canonical(value: Any) -> Optional[str]:
    """The canonical text of a valid IP address, or None when the value is missing or not an address."""
    if value in (None, ""):
        return None
    try:
        return ipaddress.ip_address(str(value).strip()).compressed
    except ValueError:
        return None


def _scope(value: Any) -> Optional[str]:
    """'internal' or 'external' for a usable address. None when it is missing, not an address, or can never be a block target
    (multicast, unspecified, reserved or broadcast)."""
    address = _canonical(value)
    if address is None:
        return None
    ip = ipaddress.ip_address(address)
    if ip.is_multicast or ip.is_unspecified or ip.is_reserved or address == "255.255.255.255":
        return None
    return "internal" if any(ip in net for net in _INTERNAL_NETWORKS) else "external"


def _named_roles(alert: Dict[str, Any]) -> Tuple[Set[str], Set[str]]:
    """The addresses the alert's own text gives a role: (named as the origin, named as the target).

    The role of an address is decided by the nearer of an origin word and a target word just before it. So 'from X against Y'
    makes X the origin and Y the target, whichever field each one is stored in."""
    text = "\n".join(str(alert.get(k) or "") for k in ("alert_title", "description", "command_line"))
    origins: Set[str] = set()
    targets: Set[str] = set()
    for found in _IPV4.finditer(text):
        address = _canonical(found.group())
        if address is None:
            continue
        line_start = text.rfind("\n", 0, found.start()) + 1      # each field is its own line, so a role never leaks across fields
        before = text[max(line_start, found.start() - _ROLE_WINDOW):found.start()]
        origin_words = list(_ORIGIN_WORDS.finditer(before))
        target_words = list(_TARGET_WORDS.finditer(before))
        nearest_origin = origin_words[-1].end() if origin_words else -1
        nearest_target = target_words[-1].end() if target_words else -1
        if nearest_origin < 0 and nearest_target < 0:
            continue
        (origins if nearest_origin > nearest_target else targets).add(address)
    return origins, targets


def _attacker(alert: Dict[str, Any]) -> Tuple[Optional[str], str]:
    """The external address the alert names as the origin of the activity, with the basis for naming it.

    Only the alert's text decides, and only between the addresses its fields carry: field names are never trusted. Returns
    (None, reason) when the text does not establish one external origin: no usable address, no direction words, more than one
    origin, the same address named as both origin and target, or an internal origin."""
    candidates = {a for a in (_canonical(alert.get("source_ip")), _canonical(alert.get("destination_ip"))) if a and _scope(a)}
    if not candidates:
        return None, "no usable IP address is recorded on the alert"
    origins, targets = _named_roles(alert)
    origins, targets = origins & candidates, targets & candidates
    if origins & targets:
        return None, "the alert text names the same address as both origin and target"
    if len(origins) > 1:
        return None, "the alert text names more than one origin"
    if origins:
        attacker = next(iter(origins))
        basis = f"the alert text names {attacker} as the origin of the failed logins"
    elif len(targets) == 1 and len(candidates) == 2:
        named = next(iter(targets))
        attacker = next(iter(candidates - {named}))
        basis = f"the alert text names {named} as the target, so {attacker} is the origin"
    else:
        return None, "the alert text does not say which address is the origin"
    if _scope(attacker) != "external":
        return None, f"{attacker} is an internal address, which is not proposed for a perimeter block"
    return attacker, basis


def _direction_of(alert: Dict[str, Any], address: str) -> Tuple[str, str]:
    """What the alert's own text says about the direction of traffic involving an address: (role, reason).

    role is 'outbound' (the host connected to the address), 'inbound' (the address connected to the host), 'ambiguous' (the text
    gives conflicting directions) or 'unknown' (the text does not say). A flagged address alone never gives a direction."""
    origins, targets = _named_roles(alert)
    if address in targets and address in origins:
        return "ambiguous", f"the alert text gives conflicting directions for {address}"
    if address in targets:
        external_origins = sorted(o for o in origins if _scope(o) == "external")
        if external_origins:
            return "ambiguous", (f"the alert text gives conflicting directions for {address}: "
                                 f"it names {', '.join(external_origins)} as the origin of the same traffic")
        return "outbound", f"the alert text names {address} as the target of the host's traffic"
    if address in origins:
        return "inbound", f"the alert text names {address} as the origin of the traffic, so it is inbound, not outbound"
    return "unknown", "the alert does not state the direction of the traffic"


def _unique_alerts(alerts) -> List[Dict[str, Any]]:
    """The alerts once each, in the order first seen."""
    seen: Dict[Any, Dict[str, Any]] = {}
    for alert in alerts:
        seen.setdefault(alert.get("id"), alert)
    return list(seen.values())


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
            live = _uses_live_intel(alerts)
            caveat = LIVE_INTEL_CAVEAT if live else MOCK_INTEL_CAVEAT
            source = "VirusTotal (not independently verified)" if live else "MOCK intelligence (unverified)"
            risk_basis = "VirusTotal engine verdicts can include false positives" if live else "the intelligence behind it is a mock"
            file_risk = ("VirusTotal engine verdicts can include false positives, so the file may be benign." if live
                         else "The intelligence is a mock, so the file may be benign.")
            domain_risk = ("VirusTotal engine verdicts can include false positives, so the domain may be legitimate." if live
                           else "The intelligence is a mock, so the domain may be legitimate.")
            # An outbound block needs BOTH the alert's own statement that the host connected to an external address AND a MALICIOUS
            # threat-intelligence verdict for that address, recorded as the alert's destination. A keyword alone, a verdict alone, or
            # a flagged address in a source field is never enough. Every address that is not blocked is explained, and an internal
            # address is never proposed for a perimeter block.
            bad_ips = {_canonical(v) for v in _flagged_iocs(alerts, "IP")}     # addresses rated MALICIOUS by the threat intelligence
            blocks: Dict[str, List[Tuple[Dict[str, Any], str]]] = {}
            unexplained: Dict[str, Tuple[List[Dict[str, Any]], str, str]] = {}   # address -> (alerts, reason, kind)
            for a in alerts:
                src, dst = _canonical(a.get("source_ip")), _canonical(a.get("destination_ip"))
                keyword = _has(a, ["c2", "command & control", "command and control", "beacon"])
                for x in sorted({v for v in (src, dst) if v}):
                    malicious = x in bad_ips and _scope(x) == "external"
                    if not (malicious or (keyword and x == dst)):
                        continue
                    if _scope(x) != "external":
                        kind, reason = "internal", "it is an internal address, which is never proposed for a perimeter block"
                    else:
                        role, basis = _direction_of(a, x)
                        if role == "outbound" and x != dst:
                            role, basis = "ambiguous", (f"the alert records {x} as its source address, but its text says the host "
                                                        "connected to it, so the record conflicts")
                        if role == "outbound" and malicious:
                            blocks.setdefault(x, []).append((a, basis))
                            continue
                        if role == "outbound":
                            kind, reason = "verdict", ("the alert states the host connected to it, but threat intelligence does not rate it "
                                                       "malicious, and a command-and-control keyword alone is not grounds for an outbound block")
                        elif role == "unknown" and x == src and x != dst:
                            kind, reason = "direction", ("it is recorded only as a source address, and the alert does not state that the host "
                                                         "connected to it")
                        else:
                            kind, reason = "direction", basis
                    unexplained.setdefault(x, ([], reason, kind))[0].append(a)
            if blocks:
                block_targets = sorted(blocks)
                block_alerts = _unique_alerts(a for x in block_targets for a, _ in blocks[x])
                bases = "; ".join(sorted({basis for x in block_targets for _, basis in blocks[x]}))
                add(3, "ioc_blocking", f"Block outbound traffic to {', '.join(block_targets)} at the perimeter firewall", ", ".join(block_targets),
                    f"Hosts communicated with a destination flagged by command-and-control alerts or {source}; {bases}.", block_alerts, "LOW",
                    benefit="Cuts the command-and-control channel and prevents data leaving to that destination.",
                    operational="Legitimate traffic to the same address (shared hosting, CDN) would also be blocked.",
                    risk=f"Blocking an address that is actually legitimate disrupts business traffic; {risk_basis}.",
                    rollback="Delete the firewall rule.",
                    approvals=["Network/Firewall owner"],
                    preconditions=[caveat, "Check that no business service uses the destination."],
                    validation=["Confirm blocked connection attempts appear in the firewall logs.", "Confirm no business application reports failures."])
            explained = {x: info for x, info in unexplained.items() if x not in blocks}
            for kind, template, validation in (
                ("direction", "Confirm the direction of traffic involving {addrs} before any outbound block",
                 ["Confirm from the connection logs whether the host connected to the address."]),
                ("verdict", "Check the threat-intelligence verdict for {addrs} before any outbound block",
                 ["Confirm the address carries a MALICIOUS rating from the threat-intelligence source before any outbound block."]),
                ("internal", "Do not block {addrs} at the perimeter: it is an internal address, so review its activity as an internal host",
                 ["Confirm the address is an internal host and not an external destination."]),
            ):
                addresses = sorted(x for x in explained if explained[x][2] == kind)
                if not addresses:
                    continue
                kind_alerts = _unique_alerts(a for x in addresses for a in explained[x][0])
                reasons = "; ".join(f"{x}: {explained[x][1]}" for x in addresses)
                add(8, "investigation", template.format(addrs=", ".join(addresses)), ", ".join(addresses),
                    f"No outbound block is proposed for these addresses: {reasons}.", kind_alerts, "NONE",
                    benefit="Keeps an address that is not established as outbound, or not rated malicious, off the firewall until it is checked.",
                    operational="None; no change is made to any system.",
                    risk="An outbound block without both the stated direction and a malicious rating can block a legitimate or internal address.",
                    rollback="Not applicable.",
                    approvals=["SOC Analyst"],
                    preconditions=["Read the raw connection logs and the threat-intelligence record for the address before deciding on any block."],
                    validation=validation)
            hashes = _flagged_iocs(alerts, "SHA256") + _flagged_iocs(alerts, "SHA1") + _flagged_iocs(alerts, "MD5")
            if hashes:
                hm = [a for a in alerts if a.get("file_hash") in hashes] or alerts
                add(6, "ioc_blocking", f"Add file hash(es) {', '.join(h[:16] + '...' for h in hashes[:3])} to the endpoint blocklist and scan for other copies",
                    ", ".join(hashes[:3]), f"File hash(es) were rated malicious by {source}.", hm, "LOW",
                    benefit="Prevents the file from running again on managed endpoints and finds other copies.",
                    operational="A wrongly blocked file stops working on every endpoint.",
                    risk=file_risk,
                    rollback="Remove the hash from the blocklist.",
                    approvals=["Endpoint security owner"],
                    preconditions=[caveat, "Confirm the file is not a legitimate tool."],
                    validation=["Confirm the blocklist entry is active.", "Review the scan results for other hosts."])
            domains = _flagged_iocs(alerts, "DOMAIN")
            if domains:
                add(6, "ioc_blocking", f"Block DNS resolution of {', '.join(domains[:5])} at the DNS/proxy layer", ", ".join(domains[:5]),
                    f"Domain(s) were rated malicious by {source}.", alerts, "LOW",
                    benefit="Prevents hosts from reaching attacker-controlled domains.",
                    operational="Legitimate use of the domain would be blocked.",
                    risk=domain_risk,
                    rollback="Remove the DNS/proxy block rule.",
                    approvals=["Network/Security operations owner"],
                    preconditions=[caveat],
                    validation=["Confirm lookups for the domain are refused.", "Confirm no business application reports failures."])
            m = match(["brute force", "failed ssh", "failed password", "failed login", "password spray"])
            if m:
                # The origin is the address the alert's own text names as the attacker, never a field name. Where the text does not
                # establish it, no IP address is proposed: the lockout/MFA step and a check of the raw logs remain.
                tgt = ', '.join(sorted({a['host'] for a in m if a.get('host')}))
                resolved, unresolved = [], []
                for a in m:
                    attacker, basis = _attacker(a)
                    (resolved if attacker else unresolved).append((a, attacker, basis))
                attackers = sorted({attacker for _, attacker, _ in resolved})
                if attackers:
                    bases = "; ".join(sorted({basis for _, _, basis in resolved}))
                    note = f" {len(unresolved)} other alert(s) do not establish the origin and are not blocked." if unresolved else ""
                    add(4, "ioc_blocking", f"Rate-limit or block the remote source {', '.join(attackers)} and enforce lockout/MFA on {tgt}", ", ".join(attackers),
                        f"Repeated failed authentication from {', '.join(attackers)}: {bases}.{note}", [a for a, _, _ in resolved], "LOW",
                        benefit="Stops further password guessing from the origin address against the target.",
                        operational="Users behind a shared address, or who mistype passwords, may be locked out.",
                        risk="Blocking a shared or internal address locks out legitimate users. The origin comes from the alert text, so confirm it in the raw logs.",
                        rollback="Remove the rate limit/block rule and unlock the affected accounts.",
                        approvals=["Network/Firewall owner", "Identity/IAM owner"],
                        preconditions=["Confirm in the raw logs that the origin address is an external attacker, not an internal or partner system."],
                        validation=["Confirm failed attempts from the origin stop.", "Confirm legitimate users can still sign in."])
                else:
                    reasons = "; ".join(sorted({basis for _, _, basis in unresolved})) or "no alert establishes the origin"
                    add(4, "credentials", f"Enforce lockout/MFA on {tgt} and confirm the source address before any IP block", tgt,
                        f"Repeated failed authentication indicates a brute-force attempt, but no IP address is proposed for blocking because {reasons}.",
                        m, "LOW",
                        benefit="Stops password guessing against the target accounts without blocking an address that may be the victim.",
                        operational="Accounts that mistype passwords may be locked out or required to use MFA.",
                        risk="Locking accounts does not stop the attacker's address, and the origin must be identified before any block.",
                        rollback="Unlock the accounts and remove the MFA requirement.",
                        approvals=["Identity/IAM owner", "SOC Analyst"],
                        preconditions=["Read the raw failed-login records to identify the origin address before any IP block."],
                        validation=["Confirm lockout or MFA applies to the affected accounts."])
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
            r.update({"id": f"REC-{i}", "requires_approval": True, "status": "PENDING", "executed": False, "simulation_status": "NOT_RUN"})
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
