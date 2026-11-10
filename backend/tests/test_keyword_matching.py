"""Boundary-aware keyword matching (C7).

A keyword must match a whole term, not a fragment of a longer word: 'c2' must not fire on 'ec2', and 'iam' must not fire on
'william'. The same rule is applied by triage, investigation and response, so each agent is tested directly.
"""
from app.agents.investigation.investigation_agent import InvestigationAgent
from app.agents.response.response_agent import ResponseAgent
from app.agents.triage.triage_agent import TriageAgent


def _alert(**fields):
    base = {"id": "KW-1", "alert_title": "", "description": "", "command_line": "", "severity": "LOW", "host": "HOST-1",
            "username": None, "source_ip": None, "destination_ip": None, "file_hash": None, "normalized_data": {}}
    base.update(fields)
    return base


def test_term_matcher_respects_word_boundaries():
    from app.agents.text_match import contains_term
    assert not contains_term("ec2 instance started", "c2")          # 'c2' inside 'ec2'
    assert not contains_term("spec2 build finished", "c2")
    assert not contains_term("william logged in", "iam")            # 'iam' inside 'william'
    assert not contains_term("arc4 cipher in use", "rc4")           # 'rc4' inside 'arc4'
    assert contains_term("rc4 cipher in use", "rc4")
    assert contains_term("c2 beacon detected", "c2")
    assert contains_term("traffic to c2-server", "c2")              # a hyphen ends a term
    assert contains_term("c2:443 connection", "c2")
    assert contains_term("iam policy changed", "iam")
    assert contains_term("powershell.exe launched", "powershell")
    assert contains_term("powershell -e JAB0AHMA", "-e ")           # a term that starts/ends with a space or dash keeps its edges
    assert not contains_term("powershell -exec bypass", "-e ")


def test_triage_does_not_read_c2_inside_ec2():
    result = TriageAgent().analyze_alert(_alert(alert_title="EC2 instance health check", description="Routine check on ec2 host"))
    assert not [i for i in result["indicators"] if "keyword matched" in i], result["indicators"]


def test_triage_still_matches_a_real_c2_keyword_and_beaconing():
    result = TriageAgent().analyze_alert(_alert(alert_title="Beaconing to c2 server", description=""))
    assert any("'c2'" in i for i in result["indicators"])
    assert any("High-impact threat category keyword matched" in i for i in result["indicators"])


def test_investigation_does_not_read_iam_inside_william():
    alerts = [_alert(alert_title="William Smith opened the finance share")]
    rules = InvestigationAgent._hypotheses(alerts, [])
    assert not [r for r in rules if r["technique"] == "T1098"], rules


def test_investigation_still_reads_iam_as_a_word():
    alerts = [_alert(alert_title="IAM policy attachment on a privileged role")]
    rules = InvestigationAgent._hypotheses(alerts, [])
    assert any(r["technique"] == "T1098" for r in rules)


def test_investigation_does_not_read_c2_inside_ec2():
    alerts = [_alert(alert_title="EC2 instance restarted", description="ec2 maintenance window")]
    rules = InvestigationAgent._hypotheses(alerts, [])
    assert not [r for r in rules if r["technique"] == "T1071"], rules


def test_response_does_not_treat_william_as_an_iam_account_change():
    alerts = [_alert(alert_title="William Smith opened the finance share", username="william")]
    rec = ResponseAgent().recommend({"severity": "LOW"}, alerts, {"evidence_strength": "moderate", "findings": []})
    assert not [r for r in rec["recommendations"] if r["category"] == "credentials"], rec["recommendations"]


def test_response_still_matches_kerberoasting_in_full():
    alerts = [_alert(alert_title="Kerberoasting activity against svc-sql")]
    rec = ResponseAgent().recommend({"severity": "HIGH"}, alerts, {"evidence_strength": "moderate", "findings": []})
    assert any(r["category"] == "credentials" for r in rec["recommendations"]), rec["recommendations"]


def test_response_c2_check_does_not_read_ec2():
    # 'ec2' must not count as the 'c2' keyword, so the address is never explained as a keyword-only case
    alerts = [_alert(alert_title="EC2 host connected to 185.220.101.5", destination_ip="185.220.101.5", source_ip="10.0.0.5")]
    rec = ResponseAgent().recommend({"severity": "LOW"}, alerts, {"evidence_strength": "moderate", "findings": []})
    text = " ".join(r["justification"] for r in rec["recommendations"])
    assert "command-and-control keyword" not in text, text
