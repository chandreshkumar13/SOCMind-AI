"""Triage findings are labelled 'computed' (C9): derived by deterministic rules from the alert's own fields, not from intelligence."""
from app.agents.triage.triage_agent import TriageAgent


def _alert(**fields):
    base = {"id": "CF-1", "alert_title": "", "description": "", "command_line": "", "severity": "HIGH", "host": "H",
            "username": None, "source_ip": None, "destination_ip": None, "file_hash": None}
    base.update(fields)
    return base


def test_each_triage_finding_is_labelled_computed_and_matches_an_indicator():
    result = TriageAgent().analyze_alert(_alert(alert_title="Ransomware activity", source_ip="10.0.0.5"))
    assert result["findings"], result
    assert all(f["type"] == "computed" for f in result["findings"])
    assert [f["statement"] for f in result["findings"]] == result["indicators"]


def test_computed_findings_say_what_they_are_based_on():
    result = TriageAgent().analyze_alert(_alert(alert_title="Ransomware activity"))
    basis = result["findings"][0]["basis"]
    assert "alert" in basis and "not" in basis and "intelligence" in basis


def test_an_alert_with_no_indicators_has_no_computed_findings():
    result = TriageAgent().analyze_alert(_alert(severity="INFO"))
    assert result["indicators"] == [] and result["findings"] == []
