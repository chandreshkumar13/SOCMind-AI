"""Decision integrity: a recorded decision is never stranded, and never silently lost.

C1 - Re-investigating an APPROVED or REJECTED incident invalidates the recommendations that decision was made on.
     The decision is therefore withdrawn (APPROVAL_RESET audit entry, full review history kept), so the incident can be
     regenerated and decided again instead of being stuck with stale recommendations.
C2 - When an incident is merged into another, a decision recorded on the merged-away incident is withdrawn in the same
     way, instead of being left behind on a MERGED record while its alerts move to an undecided incident.

Only the public API and the database rows are used; no network is needed.
"""
import pytest

from app.models.models import IncidentModel


# ------------------------------------------------------------------ helpers
def _seed_and_run(client):
    client.post("/api/v1/alerts/seed")
    return client.post("/api/v1/pipeline/run").json()


def _finance(client):
    return next(i["id"] for i in client.get("/api/v1/incidents").json() if "ALT-2026-001" in i["correlated_alert_ids"])


def _get(client, inc_id):
    return client.get(f"/api/v1/incidents/{inc_id}").json()


def _audit(client, action, target=None):
    params = {"action": action, **({"target_id": target} if target else {})}
    return client.get("/api/v1/audit-logs", params=params).json()


def _edit_incident(client, inc_id, change):
    db = client.session_factory()
    try:
        row = db.query(IncidentModel).filter(IncidentModel.id == inc_id).one()
        change(row)
        db.commit()
    finally:
        db.close()


# ------------------------------------------------------------------ C1: re-investigating a decided incident
def test_reinvestigating_an_approved_incident_withdraws_the_decision_and_keeps_its_history(iso_client):
    _seed_and_run(iso_client)
    inc = _finance(iso_client)
    assert iso_client.post(f"/api/v1/incidents/{inc}/approve", json={"reviewer": "Analyst A", "reason": "ok"}).status_code == 200

    res = iso_client.post(f"/api/v1/incidents/{inc}/investigate")
    assert res.status_code == 200
    body = res.json()
    assert body["human_approval_status"] == "PENDING" and body["status"] == "INVESTIGATED"
    assert "review" not in body["details"]
    (old,) = body["details"]["review_history"]
    assert old["review"]["decision"] == "APPROVED" and old["review"]["reviewer"] == "Analyst A"
    assert "re-investigation" in old["superseded_by"]
    (reset,) = _audit(iso_client, "APPROVAL_RESET", inc)
    assert reset["actor"] == "Investigation Agent"
    assert reset["details"]["previous"] == "APPROVED"


def test_reinvestigating_a_rejected_incident_withdraws_the_rejection(iso_client):
    _seed_and_run(iso_client)
    inc = _finance(iso_client)
    assert iso_client.post(f"/api/v1/incidents/{inc}/reject", json={"reviewer": "Analyst A"}).status_code == 200

    body = iso_client.post(f"/api/v1/incidents/{inc}/investigate").json()
    assert body["human_approval_status"] == "PENDING"
    (old,) = body["details"]["review_history"]
    assert old["review"]["decision"] == "REJECTED" and old["review"]["reviewer"] == "Analyst A"
    assert _audit(iso_client, "APPROVAL_RESET", inc)[0]["details"]["previous"] == "REJECTED"


def test_reinvestigating_a_simulated_incident_moves_the_simulation_into_history(iso_client):
    _seed_and_run(iso_client)
    inc = _finance(iso_client)
    assert iso_client.post(f"/api/v1/incidents/{inc}/approve", json={"reviewer": "Analyst A"}).status_code == 200
    assert iso_client.post(f"/api/v1/incidents/{inc}/simulate", json={"reviewer": "Analyst B"}).status_code == 200

    body = iso_client.post(f"/api/v1/incidents/{inc}/investigate").json()
    assert body["human_approval_status"] == "PENDING"
    assert "simulation" not in body["details"]
    (old,) = body["details"]["review_history"]
    assert old["review"]["decision"] == "APPROVED" and old["simulation"]["simulated_by"] == "Analyst B"


def test_a_reinvestigated_incident_can_be_recommended_and_decided_again(iso_client):
    _seed_and_run(iso_client)
    inc = _finance(iso_client)
    assert iso_client.post(f"/api/v1/incidents/{inc}/approve", json={"reviewer": "Analyst A"}).status_code == 200
    assert iso_client.post(f"/api/v1/incidents/{inc}/investigate").status_code == 200

    recommended = iso_client.post(f"/api/v1/incidents/{inc}/recommend")
    assert recommended.status_code == 200 and recommended.json()["human_approval_status"] == "PENDING"
    approved = iso_client.post(f"/api/v1/incidents/{inc}/approve", json={"reviewer": "Analyst B"})
    assert approved.status_code == 200 and approved.json()["status"] == "RESPONSE_APPROVED"
    assert approved.json()["details"]["review"]["reviewer"] == "Analyst B"
    assert [h["review"]["reviewer"] for h in approved.json()["details"]["review_history"]] == ["Analyst A"]


def test_each_withdrawn_decision_stays_in_the_history_in_order(iso_client):
    _seed_and_run(iso_client)
    inc = _finance(iso_client)
    for reviewer in ("Analyst A", "Analyst B"):
        assert iso_client.post(f"/api/v1/incidents/{inc}/recommend").status_code == 200
        assert iso_client.post(f"/api/v1/incidents/{inc}/approve", json={"reviewer": reviewer}).status_code == 200
        assert iso_client.post(f"/api/v1/incidents/{inc}/investigate").status_code == 200
    body = _get(iso_client, inc)
    assert body["human_approval_status"] == "PENDING"
    assert [h["review"]["reviewer"] for h in body["details"]["review_history"]] == ["Analyst A", "Analyst B"]
    assert len(_audit(iso_client, "APPROVAL_RESET", inc)) == 2


def test_reinvestigating_a_pending_incident_changes_no_decision(iso_client):
    """Behaviour that must not change: nothing was decided, so nothing is withdrawn."""
    _seed_and_run(iso_client)
    inc = _finance(iso_client)
    body = iso_client.post(f"/api/v1/incidents/{inc}/investigate").json()
    assert body["human_approval_status"] == "PENDING" and body["details"]["recommendations_stale"] is True
    assert not body["details"].get("review_history")
    assert _audit(iso_client, "APPROVAL_RESET", inc) == []


# ------------------------------------------------------------------ C2: merging an incident that has a decision
def _two_open_incidents_sharing_an_alert(client):
    """Two open incidents on two hosts. Returns (kept, other, shared): `kept` is the lower id (the one a merge keeps),
    `other` the higher id, and `shared` an alert of `kept` that is not yet listed in `other`."""
    for alert_id, host in [("MRG-P", "MERGE-H1"), ("MRG-Q", "MERGE-H1"), ("MRG-R", "MERGE-H2"), ("MRG-S", "MERGE-H2")]:
        res = client.post("/api/v1/alerts", json={"id": alert_id, "alert_title": "merge test", "host": host,
                                                  "timestamp": "2026-09-03T08:00:00Z"})
        assert res.status_code == 201
    assert client.post("/api/v1/incidents/correlate").status_code == 200
    owner = {a: i["id"] for i in client.get("/api/v1/incidents").json() for a in i["correlated_alert_ids"]}
    assert owner["MRG-P"] != owner["MRG-R"]
    kept, other = sorted([owner["MRG-P"], owner["MRG-R"]])
    shared = next(a for a, inc in owner.items() if inc == kept)
    return kept, other, shared


def _list_alert_in_incident(client, alert_id, inc_id):
    """Puts an alert into a second incident's list, as data written before correlation could leave it."""
    _edit_incident(client, inc_id, lambda row: setattr(row, "correlated_alert_ids", sorted(set(row.correlated_alert_ids) | {alert_id})))


@pytest.mark.parametrize("decision,decided", [("approve", "APPROVED"), ("reject", "REJECTED")])
def test_merging_an_incident_withdraws_a_decision_recorded_on_it(iso_client, decision, decided):
    kept, other, shared = _two_open_incidents_sharing_an_alert(iso_client)
    assert iso_client.post(f"/api/v1/incidents/{other}/recommend").status_code == 200
    assert iso_client.post(f"/api/v1/incidents/{other}/{decision}", json={"reviewer": "Analyst A"}).status_code == 200
    _list_alert_in_incident(iso_client, shared, other)

    assert iso_client.post("/api/v1/incidents/correlate").status_code == 200

    merged = _get(iso_client, other)
    assert merged["status"] == "MERGED"
    assert merged["human_approval_status"] == "PENDING"                    # the decision is no longer in force
    (old,) = merged["details"]["review_history"]                           # ...but it is kept, complete
    assert old["review"]["decision"] == decided and old["review"]["reviewer"] == "Analyst A"
    assert f"merged into {kept}" in old["superseded_by"]
    (reset,) = _audit(iso_client, "APPROVAL_RESET", other)
    assert reset["actor"] == "Correlation Agent" and reset["details"]["previous"] == decided
    assert _audit(iso_client, "INCIDENT_MERGED", other)                    # the merge itself is still recorded

    survivor = _get(iso_client, kept)
    assert survivor["status"] != "MERGED" and survivor["human_approval_status"] == "PENDING"
    assert set(survivor["correlated_alert_ids"]) == {"MRG-P", "MRG-Q", "MRG-R", "MRG-S"}


def test_merging_an_undecided_incident_writes_no_reset(iso_client):
    """Behaviour that must not change: a merge of an incident nobody decided is unaffected."""
    kept, other, shared = _two_open_incidents_sharing_an_alert(iso_client)
    _list_alert_in_incident(iso_client, shared, other)

    assert iso_client.post("/api/v1/incidents/correlate").status_code == 200
    merged = _get(iso_client, other)
    assert merged["status"] == "MERGED" and merged["human_approval_status"] == "PENDING"
    assert not merged["details"].get("review_history")
    assert _audit(iso_client, "APPROVAL_RESET", other) == []


# ------------------------------------------------------------------ superseded recommendations
def test_withdrawn_recommendations_are_superseded_not_current(iso_client):
    _seed_and_run(iso_client)
    inc = _finance(iso_client)
    assert iso_client.post(f"/api/v1/incidents/{inc}/approve", json={"reviewer": "Analyst A"}).status_code == 200

    body = iso_client.post(f"/api/v1/incidents/{inc}/investigate").json()
    recs = body["details"]["recommendations"]
    assert recs and all(r["status"] == "SUPERSEDED" and r["simulation_status"] == "SUPERSEDED" for r in recs)
    assert all(r["executed"] is False for r in recs)
    assert all("re-investigation" in r["superseded_by"] and r["superseded_at"].endswith("Z") for r in recs)
    assert not any(r["status"] in ("APPROVED", "REJECTED") for r in recs)


def test_a_withdrawn_simulation_keeps_its_recommendations_as_they_were(iso_client):
    _seed_and_run(iso_client)
    inc = _finance(iso_client)
    assert iso_client.post(f"/api/v1/incidents/{inc}/approve", json={"reviewer": "Analyst A"}).status_code == 200
    assert iso_client.post(f"/api/v1/incidents/{inc}/simulate", json={"reviewer": "Analyst B"}).status_code == 200
    simulated_actions = [r["action"] for r in _get(iso_client, inc)["details"]["recommendations"]]

    body = iso_client.post(f"/api/v1/incidents/{inc}/investigate").json()
    (old,) = body["details"]["review_history"]
    assert old["simulation"]["simulated_by"] == "Analyst B" and old["review"]["decision"] == "APPROVED"
    snapshot = old["recommendations"]                                  # the set exactly as the decision saw it
    assert [r["action"] for r in snapshot] == simulated_actions
    assert snapshot and all(r["status"] == "APPROVED" and r["simulation_status"] == "SIMULATED" and r["executed"] is False
                            for r in snapshot)
    assert all(r["status"] == "SUPERSEDED" for r in body["details"]["recommendations"])


def test_withdrawal_clears_the_primary_action_and_keeps_it_in_history(iso_client):
    _seed_and_run(iso_client)
    inc = _finance(iso_client)
    primary = _get(iso_client, inc)["recommended_action"]
    assert primary
    assert iso_client.post(f"/api/v1/incidents/{inc}/approve", json={"reviewer": "Analyst A"}).status_code == 200

    body = iso_client.post(f"/api/v1/incidents/{inc}/investigate").json()
    assert body["recommended_action"] is None
    assert body["details"]["review_history"][0]["recommended_action"] == primary


def test_a_withdrawal_erases_no_audit_entry(iso_client):
    """Behaviour that must not change: the audit trail keeps every earlier event."""
    _seed_and_run(iso_client)
    inc = _finance(iso_client)
    assert iso_client.post(f"/api/v1/incidents/{inc}/approve", json={"reviewer": "Analyst A"}).status_code == 200
    before = {a: len(_audit(iso_client, a, inc)) for a in ("INCIDENT_APPROVED", "RESPONSE_RECOMMENDED", "INCIDENT_INVESTIGATED")}

    assert iso_client.post(f"/api/v1/incidents/{inc}/investigate").status_code == 200
    after = {a: len(_audit(iso_client, a, inc)) for a in before}
    assert all(after[a] >= before[a] for a in before)
    assert after["INCIDENT_APPROVED"] == 1 and len(_audit(iso_client, "APPROVAL_RESET", inc)) == 1


def test_regenerated_recommendations_replace_the_superseded_ones_and_the_old_set_stays_in_history(iso_client):
    _seed_and_run(iso_client)
    inc = _finance(iso_client)
    assert iso_client.post(f"/api/v1/incidents/{inc}/approve", json={"reviewer": "Analyst A"}).status_code == 200
    assert iso_client.post(f"/api/v1/incidents/{inc}/investigate").status_code == 200

    body = iso_client.post(f"/api/v1/incidents/{inc}/recommend").json()
    recs = body["details"]["recommendations"]
    assert recs and all(r["status"] == "PENDING" and "superseded_by" not in r for r in recs)
    assert body["details"]["review_history"][0]["recommendations"]     # the withdrawn set is still on record


def test_a_merged_away_incidents_recommendations_are_superseded_and_kept(iso_client):
    kept, other, shared = _two_open_incidents_sharing_an_alert(iso_client)
    assert iso_client.post(f"/api/v1/incidents/{other}/recommend").status_code == 200
    assert iso_client.post(f"/api/v1/incidents/{other}/approve", json={"reviewer": "Analyst A"}).status_code == 200
    _list_alert_in_incident(iso_client, shared, other)
    assert iso_client.post("/api/v1/incidents/correlate").status_code == 200

    merged = _get(iso_client, other)
    assert merged["status"] == "MERGED"
    assert merged["details"]["recommendations"] and all(r["status"] == "SUPERSEDED" for r in merged["details"]["recommendations"])
    assert all(r["status"] == "APPROVED" for r in merged["details"]["review_history"][0]["recommendations"])


# ------------------------------------------------------------------ merged incidents are closed to every decision and analysis step
def _merged_incident(client):
    """A merged-away incident that had been recommended and APPROVED before the merge. Returns (kept, merged)."""
    kept, other, shared = _two_open_incidents_sharing_an_alert(client)
    assert client.post(f"/api/v1/incidents/{other}/recommend").status_code == 200
    assert client.post(f"/api/v1/incidents/{other}/approve", json={"reviewer": "Analyst A"}).status_code == 200
    _list_alert_in_incident(client, shared, other)
    assert client.post("/api/v1/incidents/correlate").status_code == 200
    assert _get(client, other)["status"] == "MERGED"
    return kept, other


def _snapshot(client, inc_id):
    body = _get(client, inc_id)
    return {"status": body["status"], "human": body["human_approval_status"], "details": body["details"]}


def _audit_count(client, target):
    return len(client.get("/api/v1/audit-logs", params={"target_id": target, "limit": 200}).json())


@pytest.mark.parametrize("decision", ["approve", "reject"])
def test_a_merged_incident_refuses_a_decision(iso_client, decision):
    kept, other = _merged_incident(iso_client)
    before, audit = _snapshot(iso_client, other), _audit_count(iso_client, other)
    res = iso_client.post(f"/api/v1/incidents/{other}/{decision}", json={"reviewer": "Analyst B"})
    assert res.status_code == 409 and kept in res.json()["detail"]
    assert _snapshot(iso_client, other) == before and _audit_count(iso_client, other) == audit


def test_a_merged_incident_refuses_new_recommendations(iso_client):
    kept, other = _merged_incident(iso_client)
    before, audit = _snapshot(iso_client, other), _audit_count(iso_client, other)
    res = iso_client.post(f"/api/v1/incidents/{other}/recommend")
    assert res.status_code == 409 and kept in res.json()["detail"]
    assert _snapshot(iso_client, other) == before and _audit_count(iso_client, other) == audit


def test_a_merged_incident_refuses_reinvestigation(iso_client):
    kept, other = _merged_incident(iso_client)
    before, audit = _snapshot(iso_client, other), _audit_count(iso_client, other)
    res = iso_client.post(f"/api/v1/incidents/{other}/investigate")
    assert res.status_code == 409 and kept in res.json()["detail"]
    assert _snapshot(iso_client, other) == before and _audit_count(iso_client, other) == audit


def test_a_merged_incident_refuses_simulation_even_if_it_still_reads_approved(iso_client):
    """The state older code could leave: a merged incident that still carries an approval and fresh recommendations."""
    kept, other = _merged_incident(iso_client)

    def legacy_state(row):
        row.human_approval_status = "APPROVED"
        row.status = "RESPONSE_APPROVED"        # what an approval leaves behind; simulation claims on this status
        row.details = {**(row.details or {}), "recommendations_stale": False}
    _edit_incident(iso_client, other, legacy_state)
    before, audit = _snapshot(iso_client, other), _audit_count(iso_client, other)
    res = iso_client.post(f"/api/v1/incidents/{other}/simulate", json={"reviewer": "Analyst B"})
    assert res.status_code == 409 and kept in res.json()["detail"]
    assert _snapshot(iso_client, other) == before and _audit_count(iso_client, other) == audit


def test_withdrawing_a_decision_always_leaves_the_recommendations_stale(iso_client):
    """void_decision marks the recommendations stale on every path, so a withdrawn set can never be approved as fresh."""
    kept, other = _merged_incident(iso_client)
    assert _get(iso_client, other)["details"]["recommendations_stale"] is True


@pytest.mark.parametrize("decision", ["approve", "reject"])
def test_superseded_recommendations_cannot_be_decided_even_if_the_stale_flag_is_clear(iso_client, decision):
    _seed_and_run(iso_client)
    inc = _finance(iso_client)
    assert iso_client.post(f"/api/v1/incidents/{inc}/approve", json={"reviewer": "Analyst A"}).status_code == 200
    assert iso_client.post(f"/api/v1/incidents/{inc}/investigate").status_code == 200     # withdraws; recommendations superseded

    def clear_stale_flag(row):
        row.details = {**(row.details or {}), "recommendations_stale": False}
    _edit_incident(iso_client, inc, clear_stale_flag)
    res = iso_client.post(f"/api/v1/incidents/{inc}/{decision}", json={"reviewer": "Analyst B"})
    assert res.status_code == 409 and "superseded" in res.json()["detail"]
    body = _get(iso_client, inc)
    assert body["human_approval_status"] == "PENDING" and "review" not in body["details"]
    assert all(r["status"] == "SUPERSEDED" for r in body["details"]["recommendations"])
    assert len(_audit(iso_client, "INCIDENT_APPROVED", inc)) == 1          # only the original approval


def test_superseded_recommendations_cannot_be_simulated_even_under_an_approved_decision(iso_client):
    _seed_and_run(iso_client)
    inc = _finance(iso_client)
    assert iso_client.post(f"/api/v1/incidents/{inc}/approve", json={"reviewer": "Analyst A"}).status_code == 200

    def superseded_under_approval(row):      # a state the API cannot produce: an approval over superseded recommendations
        details = dict(row.details or {})
        details["recommendations"] = [dict(r, status="SUPERSEDED", simulation_status="SUPERSEDED") for r in details["recommendations"]]
        details["recommendations_stale"] = False
        row.details = details
    _edit_incident(iso_client, inc, superseded_under_approval)
    res = iso_client.post(f"/api/v1/incidents/{inc}/simulate", json={"reviewer": "Analyst B"})
    assert res.status_code == 409 and "superseded" in res.json()["detail"]
    assert "simulation" not in _get(iso_client, inc)["details"]


def test_the_incident_a_merge_keeps_can_still_be_recommended_and_decided(iso_client):
    """Behaviour that must not change: the surviving incident of a merge works as before."""
    kept, other = _merged_incident(iso_client)
    assert iso_client.post(f"/api/v1/incidents/{kept}/recommend").status_code == 200
    res = iso_client.post(f"/api/v1/incidents/{kept}/approve", json={"reviewer": "Analyst C"})
    assert res.status_code == 200 and res.json()["status"] == "RESPONSE_APPROVED"


# ------------------------------------------------------------------ the merge mark excludes an incident everywhere
def _legacy_status(client, inc_id, status="RESPONSE_PROPOSED"):
    """The state an older request could leave: the merge mark is still in the details, but the status was changed."""
    _edit_incident(client, inc_id, lambda row: setattr(row, "status", status))


def test_a_merged_incident_is_not_in_the_active_incident_list(iso_client):
    kept, other = _merged_incident(iso_client)
    ids = [i["id"] for i in iso_client.get("/api/v1/incidents").json()]
    assert other not in ids and kept in ids
    assert _get(iso_client, other)["details"]["merged_into"] == kept     # still retrievable for its history


def test_a_merge_mark_excludes_an_incident_from_the_list_even_when_its_status_was_changed(iso_client):
    kept, other = _merged_incident(iso_client)
    _legacy_status(iso_client, other)
    ids = [i["id"] for i in iso_client.get("/api/v1/incidents").json()]
    assert other not in ids and kept in ids
    filtered = [i["id"] for i in iso_client.get("/api/v1/incidents", params={"status": "RESPONSE_PROPOSED"}).json()]
    assert other not in filtered
    assert _get(iso_client, other)["details"]["merged_into"] == kept


def test_statistics_count_only_active_incidents_even_when_a_merged_status_was_changed(iso_client):
    kept, other = _merged_incident(iso_client)
    _legacy_status(iso_client, other, "RESPONSE_PROPOSED")
    stats = iso_client.get("/api/v1/stats").json()
    assert stats["incidents"]["total"] == 1 and len(iso_client.get("/api/v1/incidents").json()) == 1
    assert stats["incidents"]["awaiting_human_review"] == 0


def test_correlation_does_not_process_a_merged_incident_again(iso_client):
    kept, other = _merged_incident(iso_client)
    _legacy_status(iso_client, other)                                  # still carries the merge mark and a shared alert
    merged_audit = _audit(iso_client, "INCIDENT_MERGED", other)
    res = iso_client.post("/api/v1/incidents/correlate").json()
    assert res["created"] == [] and other not in res["updated"]
    assert _get(iso_client, other)["status"] == "RESPONSE_PROPOSED"
    assert _audit(iso_client, "INCIDENT_MERGED", other) == merged_audit
    assert set(_get(iso_client, kept)["correlated_alert_ids"]) == {"MRG-P", "MRG-Q", "MRG-R", "MRG-S"}


def test_the_pipeline_does_not_analyse_a_merged_incident(iso_client):
    kept, other = _merged_incident(iso_client)
    _legacy_status(iso_client, other)
    _edit_incident(iso_client, other, lambda row: setattr(row, "details", {**(row.details or {}), "investigation_stale": True}))
    before = _get(iso_client, other)["details"]
    run = iso_client.post("/api/v1/pipeline/run").json()
    stages = {s["agent"]: s for s in run["stages"]}
    assert other not in stages["Investigation Agent"]["items"] and other not in stages["Response Agent"]["items"]
    assert _get(iso_client, other)["status"] == "RESPONSE_PROPOSED"
    assert _get(iso_client, other)["details"] == before


def test_enrichment_does_not_mark_a_merged_incident_stale(iso_client):
    kept, other = _merged_incident(iso_client)                          # other has analysis, so it could be marked
    _legacy_status(iso_client, other)
    assert iso_client.post("/api/v1/alerts/MRG-P/enrich").status_code == 200
    assert _audit(iso_client, "INCIDENT_STALE", other) == []
    assert not _get(iso_client, other)["details"].get("stale_reasons")
