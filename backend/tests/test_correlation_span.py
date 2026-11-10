"""Correlation span rule (C12).

Each alert pair must be within the window, and so must the whole group: a chain of alerts that are each 20 hours apart may not
form one incident that spans 40 hours when the window is 24. Links that would break that rule are refused and explained.
"""
from app.agents.correlation.correlation_agent import CorrelationAgent


def _alert(alert_id, hours, host="WS-1", severity="HIGH"):
    from datetime import datetime, timedelta, timezone
    when = datetime(2026, 9, 3, 0, 0, tzinfo=timezone.utc) + timedelta(hours=hours)
    return {"id": alert_id, "timestamp": when.isoformat().replace("+00:00", "Z"), "host": host, "severity": severity,
            "alert_title": f"alert {alert_id}", "status": "NEW", "source_ip": None, "destination_ip": None,
            "file_hash": None, "username": None}


def test_a_chain_longer_than_the_window_is_not_joined_into_one_incident():
    agent = CorrelationAgent()
    alerts = [_alert("A", 0), _alert("B", 20), _alert("C", 40)]   # each pair is 20 h apart; A and C are 40 h apart
    groups = agent.correlate_alerts(alerts, window_hours=24)
    assert len(groups) == 1
    assert sorted(groups[0]["alert_ids"]) == ["A", "B"]           # C is left out rather than stretching the incident
    assert all(g["span_hours"] <= 24 for g in groups)


def test_a_chain_within_the_window_is_still_one_incident():
    agent = CorrelationAgent()
    groups = agent.correlate_alerts([_alert("A", 0), _alert("B", 10), _alert("C", 20)], window_hours=24)
    assert len(groups) == 1
    assert groups[0]["alert_ids"] == ["A", "B", "C"]
    assert groups[0]["span_hours"] == 20


def test_the_refused_link_is_explained_with_the_alerts_and_the_span():
    agent = CorrelationAgent()
    agent.correlate_alerts([_alert("A", 0), _alert("B", 20), _alert("C", 40)], window_hours=24)
    refusals = agent.last_span_refusals
    assert len(refusals) == 1
    refusal = refusals[0]
    assert refusal["alert_ids"] == ["B", "C"]
    assert refusal["fields"] == ["host"]
    assert refusal["span_hours"] == 40 and refusal["window_hours"] == 24
    assert "40" in refusal["reason"] and "24-hour window" in refusal["reason"]


def test_the_group_explains_its_span_against_the_window():
    agent = CorrelationAgent()
    groups = agent.correlate_alerts([_alert("A", 0), _alert("B", 15)], window_hours=24)
    assert groups[0]["span_hours"] == 15
    assert groups[0]["window_hours"] == 24
    assert any("15" in r and "24-hour window" in r for r in groups[0]["reasons"]), groups[0]["reasons"]


def test_the_result_does_not_depend_on_the_order_the_alerts_arrive_in():
    alerts = [_alert("A", 0), _alert("B", 20), _alert("C", 40), _alert("D", 42)]
    forward = CorrelationAgent().correlate_alerts(alerts, window_hours=24)
    backward = CorrelationAgent().correlate_alerts(list(reversed(alerts)), window_hours=24)
    assert [g["alert_ids"] for g in forward] == [g["alert_ids"] for g in backward]
    assert all(g["span_hours"] <= 24 for g in forward)


def test_no_group_ever_exceeds_the_window_even_with_many_alerts():
    agent = CorrelationAgent()
    alerts = [_alert(f"X{i:02d}", i * 5) for i in range(12)]           # one host, a 55-hour run of alerts
    groups = agent.correlate_alerts(alerts, window_hours=24)
    assert groups, "some alerts should still correlate"
    assert all(g["span_hours"] <= 24 for g in groups)


def test_an_incident_stored_by_the_pipeline_keeps_its_span_and_refusals(iso_client):
    # 2026-09-03T00:00Z, 20 h later, and 40 h later: the third alert cannot join the first two within a 24 h window
    stamps = {"SPAN-A": "2026-09-03T00:00:00Z", "SPAN-B": "2026-09-03T20:00:00Z", "SPAN-C": "2026-09-04T16:00:00Z"}
    for alert_id, stamp in stamps.items():
        body = {"id": alert_id, "alert_title": "Span test", "source": "CrowdStrike EDR", "severity": "HIGH", "host": "SPAN-HOST",
                "timestamp": stamp}
        assert iso_client.post("/api/v1/alerts", json=body).status_code == 201
    result = iso_client.post("/api/v1/incidents/correlate", json={"window_hours": 24}).json()
    assert result.get("span_refusals"), result                       # the refused link is reported to the caller
    stored = iso_client.get("/api/v1/incidents").json()
    assert len(stored) == 1
    correlation = iso_client.get(f"/api/v1/incidents/{stored[0]['id']}").json()["details"]["correlation"]
    assert "span_hours" in correlation and correlation["span_hours"] <= 24
    assert correlation["window_hours"] == 24
