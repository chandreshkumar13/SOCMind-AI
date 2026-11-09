"""Response targets: which address a containment proposal may block, and when none may be blocked.

The attacker is taken from the alert's own account of the activity (its title, description and command line), never from a
field name: SIEMs disagree about which field carries the origin. Internal addresses are never proposed for a perimeter block.
When the alert does not establish the direction, no IP address is proposed; the lockout/MFA step and the confirm-the-source
step remain. Every recommendation is still a simulation proposal that a person must approve.
"""
import pytest

from app.agents.response.response_agent import ResponseAgent

BRUTE_TITLE = "Multiple Failed SSH Authentication Attempts"
ATTACKER = "198.51.100.77"      # external: the documentation range the synthetic data uses for external addresses
VICTIM = "10.0.0.5"             # internal


def _alert(**fields):
    base = {"id": "A-1", "alert_title": "", "description": "", "command_line": "", "host": "SSH-GATEWAY-01",
            "username": None, "source_ip": None, "destination_ip": None, "severity": "MEDIUM", "file_hash": None,
            "normalized_data": {}}
    base.update(fields)
    return base


def _brute(description, **fields):
    return _alert(id="BF-1", alert_title=BRUTE_TITLE, description=description, **fields)


def _iocs(*rows):
    """Enrichment stored on an alert: rows of (type, value, reputation, source field)."""
    return {"enrichment": {"iocs": [{"type": t, "value": v, "reputation": r, "source": s} for t, v, r, s in rows]}}


def _recs(alerts):
    out = ResponseAgent().recommend({"id": "INC-T", "severity": "HIGH"}, alerts, {"evidence_strength": "moderate", "findings": []})
    return out["recommendations"]


def _ip_blocks(recs):
    """Addresses a recommendation would block or rate-limit at the perimeter."""
    blocks = []
    for r in recs:
        if r["action"].startswith(("Rate-limit or block the remote source", "Block outbound traffic to")):
            blocks.extend(t for t in (r["target"] or "").split(", ") if t)
    return blocks


def _direction_notes(recs):
    """The recommendations that explain why an address was not proposed for an outbound block (direction, verdict or internal)."""
    return [r for r in recs if r["category"] == "investigation" and r["justification"].startswith("No outbound block is proposed")]


def _note_for(recs, address):
    return next(n for n in _direction_notes(recs) if address in n["target"])


# ---- SSH brute force: the attacker is the address the alert names as the origin, whichever field carries it
@pytest.mark.parametrize("attacker_field,victim_field", [("source_ip", "destination_ip"), ("destination_ip", "source_ip")])
def test_the_address_the_alert_names_as_the_origin_is_blocked_and_the_victim_is_not(attacker_field, victim_field):
    recs = _recs([_brute(f"50 failed login attempts from {ATTACKER} against {VICTIM} over 60 seconds.",
                         **{attacker_field: ATTACKER, victim_field: VICTIM})])
    assert _ip_blocks(recs) == [ATTACKER]
    brute = next(r for r in recs if r["action"].startswith("Rate-limit or block the remote source"))
    assert brute["target"] == ATTACKER and "lockout/MFA" in brute["action"]
    assert "as the origin" in brute["justification"]


def test_the_sample_ssh_alert_still_blocks_its_external_attacker():
    recs = _recs([_brute("50 failed login attempts detected over 60 seconds from synthetic external IP 198.51.100.77.",
                         source_ip="10.0.1.15", destination_ip=ATTACKER)])
    assert _ip_blocks(recs) == [ATTACKER]


# ---- ambiguous or conflicting direction: no address is blocked
@pytest.mark.parametrize("description", [
    f"50 failed login attempts between {ATTACKER} and {VICTIM}.",
    f"failed login attempts from {ATTACKER} and from {VICTIM} against the gateway.",
])
def test_ambiguous_or_conflicting_direction_proposes_no_ip_block(description):
    recs = _recs([_brute(description, source_ip=ATTACKER, destination_ip=VICTIM)])
    assert _ip_blocks(recs) == []
    lock = next(r for r in recs if "lockout/MFA" in r["action"])
    assert lock["target"] == "SSH-GATEWAY-01" and "before any IP block" in lock["action"] and lock["category"] == "credentials"


def test_an_internal_origin_is_never_proposed_and_the_external_target_is_not_blocked():
    recs = _recs([_brute(f"failed login attempts from {VICTIM} against {ATTACKER}.", source_ip=VICTIM, destination_ip=ATTACKER)])
    assert _ip_blocks(recs) == []


# ---- one address only
def test_a_single_address_the_alert_names_as_the_origin_is_blocked():
    recs = _recs([_brute(f"50 failed login attempts from {ATTACKER}.", destination_ip=ATTACKER)])
    assert _ip_blocks(recs) == [ATTACKER]


def test_a_single_address_without_any_direction_is_not_blocked():
    recs = _recs([_brute("50 failed login attempts detected over 60 seconds.", destination_ip=ATTACKER)])
    assert _ip_blocks(recs) == []


def test_a_single_internal_address_is_never_blocked():
    recs = _recs([_brute(f"50 failed login attempts from {VICTIM}.", source_ip=VICTIM)])
    assert _ip_blocks(recs) == []


# ---- missing addresses
def test_missing_addresses_produce_no_blank_or_guessed_block():
    recs = _recs([_brute("50 failed login attempts detected over 60 seconds.")])
    assert _ip_blocks(recs) == []
    assert not any(r["target"] == "" for r in recs)
    assert any("lockout/MFA" in r["action"] for r in recs)


# ---- command-and-control outbound blocking
# ---- outbound blocking needs the alert's own statement that the host connected to the address. A flagged address alone
#      does not establish the direction of the traffic.
def test_a_flagged_destination_the_alert_says_the_host_connected_to_is_blocked():
    recs = _recs([_alert(id="C2-1", alert_title="Beaconing detected", description="Beaconing traffic detected towards 9.9.9.9.",
                         source_ip=VICTIM, destination_ip="9.9.9.9", normalized_data=_iocs(("IP", "9.9.9.9", "MALICIOUS", "destination_ip")))])
    assert _ip_blocks(recs) == ["9.9.9.9"]
    block = next(r for r in recs if r["action"].startswith("Block outbound traffic to 9.9.9.9"))
    assert "as the target of the host's traffic" in block["justification"]
    assert block["supporting_evidence"] == ["alert:C2-1"]
    assert _direction_notes(recs) == []


def test_a_flagged_destination_without_direction_evidence_is_not_blocked_and_the_reason_is_given():
    recs = _recs([_alert(id="C2-4", alert_title="Suspicious network connection", description="Connection observed.",
                         source_ip=VICTIM, destination_ip="9.9.9.9", normalized_data=_iocs(("IP", "9.9.9.9", "MALICIOUS", "destination_ip")))])
    assert _ip_blocks(recs) == []
    notes = _direction_notes(recs)
    assert len(notes) == 1 and "9.9.9.9" in notes[0]["target"] and "does not state the direction" in notes[0]["justification"]


def test_a_flagged_address_recorded_only_as_a_source_is_not_blocked_and_is_explained():
    recs = _recs([_alert(id="C2-2", alert_title="Beaconing detected", command_line="beacon", source_ip="185.220.101.5",
                         destination_ip=VICTIM, normalized_data=_iocs(("IP", "185.220.101.5", "MALICIOUS", "source_ip")))])
    assert "185.220.101.5" not in _ip_blocks(recs)
    notes = _direction_notes(recs)
    assert notes and "185.220.101.5" in notes[0]["target"] and "only as a source address" in notes[0]["justification"]


@pytest.mark.parametrize("description,source", [
    ("Beaconing from 185.220.101.5 towards 185.220.101.5.", "185.220.101.5"),       # both directions for one address
    ("Beaconing from 203.0.113.5 towards 185.220.101.5.", "203.0.113.5"),           # an external origin for the same traffic
])
def test_an_ambiguous_direction_is_not_blocked(description, source):
    recs = _recs([_alert(id="C2-5", alert_title="Beaconing detected", description=description, source_ip=source,
                         destination_ip="185.220.101.5", normalized_data=_iocs(("IP", "185.220.101.5", "MALICIOUS", "destination_ip")))])
    assert _ip_blocks(recs) == []
    notes = _direction_notes(recs)
    assert notes and "185.220.101.5" in notes[0]["target"] and "conflicting directions" in notes[0]["justification"]


def test_an_internal_destination_is_never_proposed_for_a_perimeter_block():
    recs = _recs([_alert(id="C2-3", alert_title="Beaconing detected", description="Beaconing traffic detected towards 192.168.1.9.",
                         command_line="beacon", source_ip=VICTIM, destination_ip="192.168.1.9")])
    assert _ip_blocks(recs) == []
    notes = _direction_notes(recs)
    assert notes and "192.168.1.9" in notes[0]["target"] and "internal address" in notes[0]["justification"]


# ---- other containment types are unchanged
def test_isolation_and_persistence_proposals_are_unchanged():
    alerts = [
        _alert(id="R-1", alert_title="Rapid Bulk File Renaming Activity (Possible Ransomware)", host="HR-FILE-SERVER", severity="CRITICAL"),
        _alert(id="R-2", alert_title="Suspicious Windows Registry Autorun Key Created", host="FINANCE-WKS-042", severity="HIGH",
               command_line="reg.exe add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v SecurityUpdate /d x.exe /f"),
    ]
    recs = _recs(alerts)
    actions = [r["action"] for r in recs]
    assert "Isolate host(s) HR-FILE-SERVER from the network" in actions
    assert any(a.startswith("Remove the persistence entry and run a full EDR scan on FINANCE-WKS-042") for a in actions)


# ---- API level: the proposal is generated from the stored alerts and still needs a person to approve it
def test_the_attacker_is_blocked_through_the_api_and_the_proposal_stays_a_simulation(iso_client):
    for alert_id, minute in (("BF-API-1", 0), ("BF-API-2", 2)):
        res = iso_client.post("/api/v1/alerts", json={
            "id": alert_id, "alert_title": BRUTE_TITLE, "host": "SSH-GATEWAY-01", "source_ip": ATTACKER, "destination_ip": VICTIM,
            "timestamp": f"2026-09-03T08:{minute:02d}:00Z", "description": f"50 failed login attempts from {ATTACKER} against {VICTIM}."})
        assert res.status_code == 201
    assert iso_client.post("/api/v1/incidents/correlate").status_code == 200
    inc = iso_client.get("/api/v1/incidents").json()[0]["id"]

    recs = iso_client.post(f"/api/v1/incidents/{inc}/recommend").json()["details"]["recommendations"]
    assert _ip_blocks(recs) == [ATTACKER]
    assert all(r["executed"] is False and r["status"] == "PENDING" for r in recs)
    assert iso_client.post(f"/api/v1/incidents/{inc}/approve", json={"reviewer": "Analyst"}).status_code == 200
    simulated = iso_client.post(f"/api/v1/incidents/{inc}/simulate", json={"reviewer": "Analyst"})
    assert simulated.status_code == 200 and simulated.json()["status"] == "RESPONSE_SIMULATED"
    assert all(r["executed"] is False for r in simulated.json()["details"]["recommendations"])


# ---- an outbound block needs BOTH explicit outbound direction AND a MALICIOUS threat-intelligence verdict
EXTERNAL_C2 = "198.51.100.77"   # external: the documentation range the synthetic data uses for external addresses


def _c2_alert(description, *, verdict=None, **fields):
    """An alert whose text carries a command-and-control keyword ('beacon') and, optionally, a threat-intelligence verdict for
    the external address."""
    normalized = _iocs(("IP", EXTERNAL_C2, verdict, "destination_ip")) if verdict else {}
    return _alert(id="C2-X", alert_title="Beaconing detected", description=description, command_line="beacon",
                  normalized_data=normalized, **fields)


def test_explicit_outbound_to_a_malicious_destination_is_blocked_even_with_a_keyword():
    recs = _recs([_c2_alert(f"Beaconing traffic detected towards {EXTERNAL_C2}.", verdict="MALICIOUS",
                            source_ip=VICTIM, destination_ip=EXTERNAL_C2)])
    assert _ip_blocks(recs) == [EXTERNAL_C2]
    block = next(r for r in recs if r["action"].startswith(f"Block outbound traffic to {EXTERNAL_C2}"))
    assert block["supporting_evidence"] == ["alert:C2-X"] and "as the target of the host's traffic" in block["justification"]
    assert _direction_notes(recs) == []


@pytest.mark.parametrize("verdict", [None, "CLEAN", "SUSPICIOUS", "UNKNOWN"])
def test_explicit_outbound_without_a_malicious_verdict_is_not_blocked_on_a_keyword_alone(verdict):
    recs = _recs([_c2_alert(f"Beaconing traffic detected towards {EXTERNAL_C2}.", verdict=verdict,
                            source_ip=VICTIM, destination_ip=EXTERNAL_C2)])
    assert _ip_blocks(recs) == []
    note = _note_for(recs, EXTERNAL_C2)
    assert "keyword alone" in note["justification"]
    assert note["action"].startswith(f"Check the threat-intelligence verdict for {EXTERNAL_C2}")


def test_a_malicious_destination_without_explicit_direction_is_not_blocked():
    recs = _recs([_c2_alert("Beaconing detected on the host.", verdict="MALICIOUS", source_ip=VICTIM, destination_ip=EXTERNAL_C2)])
    assert _ip_blocks(recs) == []
    note = _note_for(recs, EXTERNAL_C2)
    assert "does not state the direction" in note["justification"] and note["action"].startswith(f"Confirm the direction of traffic involving {EXTERNAL_C2}")


def test_a_destination_recorded_as_a_source_but_described_as_contacted_is_an_ambiguous_record():
    recs = _recs([_c2_alert(f"Beaconing traffic detected towards {EXTERNAL_C2}.", verdict="MALICIOUS",
                            source_ip=EXTERNAL_C2, destination_ip=VICTIM)])
    assert _ip_blocks(recs) == []
    note = _note_for(recs, EXTERNAL_C2)
    assert "as its source address" in note["justification"]
