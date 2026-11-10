"""Timestamp integrity (C4): a missing or malformed event time is never replaced by the ingestion time.

Times are stored as naive UTC. An explicit UTC offset is converted, a naive value is read as UTC, a missing value is stored as
unknown (NULL) and reported as such, and a malformed value is rejected with a clear error, so an invented time can never place
an alert on a correlation or investigation timeline.
"""
from datetime import datetime

import pytest

from app.services import normalization


def _ingest(client, **fields):
    payload = {"alert_title": "Timestamp test", "source": "Splunk SIEM", "severity": "LOW", **fields}
    return client.post("/api/v1/alerts", json=payload)


def test_a_malformed_timestamp_is_rejected_with_a_clear_error_and_nothing_is_stored(iso_client):
    res = _ingest(iso_client, id="TS-BAD-1", timestamp="09/03/2026 08:14")
    assert res.status_code == 422
    assert "ISO-8601" in res.text
    assert iso_client.get("/api/v1/alerts/TS-BAD-1").status_code == 404


def test_a_missing_timestamp_is_stored_as_unknown_and_not_as_the_ingestion_time(iso_client):
    res = _ingest(iso_client, id="TS-MISSING-1")
    assert res.status_code == 201
    body = res.json()
    assert body["timestamp"] is None
    assert body["normalized_data"]["timestamp_status"] == "missing"


def test_an_offset_timestamp_is_converted_to_utc(iso_client):
    res = _ingest(iso_client, id="TS-OFFSET-1", timestamp="2026-09-03T10:14:00+02:00")
    assert res.status_code == 201
    assert res.json()["timestamp"] == "2026-09-03T08:14:00Z"
    assert res.json()["normalized_data"]["timestamp_status"] == "given"


def test_a_naive_timestamp_is_read_as_utc(iso_client):
    res = _ingest(iso_client, id="TS-NAIVE-1", timestamp="2026-09-03T08:14:00")
    assert res.status_code == 201
    assert res.json()["timestamp"] == "2026-09-03T08:14:00Z"


def test_an_alert_without_a_known_time_is_not_correlated_and_is_reported(iso_client):
    assert _ingest(iso_client, id="TS-C-1", host="TS-HOST", timestamp="2026-09-03T08:00:00Z").status_code == 201
    assert _ingest(iso_client, id="TS-C-2", host="TS-HOST").status_code == 201    # no time: it must not be placed on a timeline
    res = iso_client.post("/api/v1/incidents/correlate").json()
    assert res["groups_found"] == 0
    assert res["alerts_without_valid_timestamp"] == ["TS-C-2"]


@pytest.mark.parametrize("raw,expected", [
    ("2026-09-03T08:14:00Z", datetime(2026, 9, 3, 8, 14)),
    ("2026-09-03T10:14:00+02:00", datetime(2026, 9, 3, 8, 14)),
    ("2026-09-03T08:14:00", datetime(2026, 9, 3, 8, 14)),
])
def test_parse_event_time_returns_naive_utc(raw, expected):
    value, status = normalization.parse_event_time(raw)
    assert value == expected and status == "given"


def test_parse_event_time_marks_absence_and_rejects_garbage():
    assert normalization.parse_event_time(None) == (None, "missing")
    assert normalization.parse_event_time("") == (None, "missing")
    with pytest.raises(ValueError, match="ISO-8601"):
        normalization.parse_event_time("yesterday afternoon")
