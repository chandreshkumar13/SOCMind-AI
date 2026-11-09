"""Keeps derived incident analysis honest when the evidence under it changes.

An incident's investigation findings and response recommendations are computed from its alerts' triage and enrichment
results. Two mechanisms keep them current:

1. Marking at change time. When an alert's enrichment is recorded and it materially differs from the previous result,
   every open incident that contains the alert and has analysis is marked stale immediately.
2. Reconciliation before each pipeline run. Every investigation records a digest of the enrichment it was built from
   (analysis_basis). Before investigating, the pipeline compares those digests with the current data, so analysis built
   before this tracking existed, or on data that changed without marking, is also refreshed.

A human decision recorded on analysis that has gone stale is withdrawn (kept in details.review_history) and the incident
returns to PENDING, so a person reviews the new recommendations. Nothing is executed: this module only changes records
and writes audit entries.
"""
import copy
import hashlib
import json
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

from sqlalchemy.orm import Session

from app.models.models import AlertModel, IncidentModel
from app.services.audit import log_action
from app.services.incident_state import active_incidents_clause

MAX_STALE_REASONS = 20
FLAGGED_REPUTATIONS = ("MALICIOUS", "SUSPICIOUS")


def now_iso() -> str:
    return datetime.utcnow().isoformat() + "Z"


def details_copy(incident: IncidentModel) -> Dict[str, Any]:
    """Deep copy of incident.details, so nested edits are always detected as a change when saved."""
    return copy.deepcopy(incident.details or {})


def enrichment_fingerprint(enrichment: Any) -> Optional[Dict[str, Any]]:
    """The parts of an enrichment result that investigation findings and recommendations are built from.

    Deliberately excluded: timestamps, retrieval times, cache hits and lookup counters (they change on every run without
    changing a verdict), and the reputation of indicators that are not flagged (the analysis never quotes them).
    So re-running an enrichment that returns the same verdicts produces the same fingerprint.
    """
    if not isinstance(enrichment, dict):
        return None
    iocs = [i for i in (enrichment.get("iocs") or []) if isinstance(i, dict)]
    return {
        "intel_mode": enrichment.get("intel_mode"),
        "provider": enrichment.get("provider"),
        "incomplete": bool(enrichment.get("incomplete")),
        "indicators": sorted([str(i.get("type")), str(i.get("value"))] for i in iocs),
        "flagged": sorted([str(i.get("type")), str(i.get("value")), str(i.get("reputation")), str(i.get("confidence")),
                           str(i.get("evidence")), str(i.get("provider"))]
                          for i in iocs if i.get("reputation") in FLAGGED_REPUTATIONS),
    }


def enrichment_digest(enrichment: Any) -> Optional[str]:
    """Stable digest of the analysis-relevant part of an enrichment result. None when there is no enrichment."""
    fingerprint = enrichment_fingerprint(enrichment)
    if fingerprint is None:
        return None
    return hashlib.sha256(json.dumps(fingerprint, sort_keys=True).encode("utf-8")).hexdigest()


def analysis_basis(alerts: List[AlertModel]) -> Dict[str, Optional[str]]:
    """What an investigation is built from: a digest of each alert's enrichment at that moment."""
    return {a.id: enrichment_digest((a.normalized_data or {}).get("enrichment")) for a in alerts}


def _source(fp: Dict[str, Any]) -> str:
    return f"{fp['intel_mode'] or 'unrecorded'}" + (f" ({fp['provider']})" if fp["provider"] else "")


def describe_enrichment_change(old: Any, new: Any) -> Optional[str]:
    """A short, human-readable description of how the enrichment changed, or None when nothing the analysis uses changed."""
    old_fp, new_fp = enrichment_fingerprint(old), enrichment_fingerprint(new)
    if old_fp == new_fp:
        return None
    if old_fp is None:
        return "enrichment recorded for the first time"
    if (old_fp["intel_mode"], old_fp["provider"]) != (new_fp["intel_mode"], new_fp["provider"]):
        return f"threat-intelligence source changed: {_source(old_fp)} -> {_source(new_fp)}"
    if old_fp["incomplete"] != new_fp["incomplete"]:
        return "lookups completed" if old_fp["incomplete"] else "lookups became incomplete"
    if old_fp["indicators"] != new_fp["indicators"]:
        return "extracted indicators changed"
    return "reputation or evidence of a flagged indicator changed"


def void_decision(db: Session, incident: IncidentModel, actor: str, reason: str) -> None:
    """Withdraws a recorded decision (and any simulation of it) because the analysis it was based on has changed.

    The old decision, its simulation and the recommendations it was based on are kept in details.review_history (the
    recommendations exactly as the decision saw them). The current recommendations are marked SUPERSEDED, so they are never
    shown as approved or simulated; the incident's primary action is cleared; the incident returns to PENDING for a new
    review; and an APPROVAL_RESET audit entry records why. Nothing is deleted. Caller commits.
    """
    previous = incident.human_approval_status
    details = details_copy(incident)
    superseded_at = now_iso()
    details.setdefault("review_history", []).append({
        "review": details.pop("review", None), "simulation": details.pop("simulation", None),
        "recommendations": copy.deepcopy(details.get("recommendations") or []),
        "recommended_action": incident.recommended_action,
        "superseded_at": superseded_at, "superseded_by": reason,
    })
    for rec in details.get("recommendations") or []:
        rec.update({"status": "SUPERSEDED", "simulation_status": "SUPERSEDED",
                    "superseded_at": superseded_at, "superseded_by": reason})
    # Whatever the decision was based on is no longer current on every withdrawal path: until the recommendations are
    # regenerated, nothing may be approved or simulated on them
    details["recommendations_stale"] = True
    incident.details = details
    incident.recommended_action = None
    log_action(db, actor, "APPROVAL_RESET", incident.id, {"reason": reason, "previous": previous})
    incident.human_approval_status = "PENDING"
    incident.status = "OPEN"


def _mark_one(db: Session, inc: IncidentModel, alert_id: Optional[str], change: str, actor: str, withdraw_reason: str) -> None:
    """Records one material change on an incident: stale flags, a reason, a withdrawn decision if any, an audit entry."""
    details = details_copy(inc)
    reasons = list(details.get("stale_reasons") or [])
    reasons.append({"alert_id": alert_id, "change": change, "at": now_iso()})
    details["stale_reasons"] = reasons[-MAX_STALE_REASONS:]
    details["investigation_stale"] = True
    details["recommendations_stale"] = True
    inc.details = details
    withdrawn = inc.human_approval_status != "PENDING"
    if withdrawn:
        void_decision(db, inc, actor, withdraw_reason)
    log_action(db, actor, "INCIDENT_STALE", inc.id, {"alert_id": alert_id, "change": change, "decision_withdrawn": withdrawn})


def mark_incidents_stale_for_alert(db: Session, alert_id: str, change: str, actor: str = "Enrichment Agent") -> List[str]:
    """Marks every open incident that contains this alert and has analysis built on it. Returns the incident ids.

    Incidents without any investigation or recommendation yet are left alone: their next run already uses the latest data.
    """
    marked: List[str] = []
    for inc in db.query(IncidentModel).filter(active_incidents_clause()).order_by(IncidentModel.id).all():
        if alert_id not in (inc.correlated_alert_ids or []):
            continue
        if not (inc.details or {}).get("investigation") and not (inc.details or {}).get("recommendations"):
            continue
        _mark_one(db, inc, alert_id, change, actor, withdraw_reason=f"threat intelligence for alert {alert_id} changed ({change})")
        marked.append(inc.id)
    return marked


def _reconcile_changes(inc: IncidentModel, alerts_by_id: Dict[str, AlertModel]) -> List[Tuple[Optional[str], str]]:
    """The changes an incident's analysis has not caught up with: (alert id or None, description)."""
    details = inc.details or {}
    members = [alerts_by_id[aid] for aid in (inc.correlated_alert_ids or []) if aid in alerts_by_id]
    basis = details.get("analysis_basis")
    if basis is None:
        return [(None, "analysis was built before change tracking; refreshing it from the latest alert data")]
    return [(a.id, "enrichment changed since this analysis was built") for a in members
            if basis.get(a.id) != enrichment_digest((a.normalized_data or {}).get("enrichment"))]


def reconcile_incidents_with_evidence(db: Session, actor: str = "Orchestrator") -> List[str]:
    """Before a pipeline run: marks incidents whose analysis was built on different alert data as stale.

    Only incidents whose analysis is currently fresh are checked (already-stale ones are refreshed anyway), and only
    incidents that have an investigation. Returns the ids that were marked. Caller commits.
    """
    alerts_by_id = {a.id: a for a in db.query(AlertModel).all()}
    marked: List[str] = []
    for inc in db.query(IncidentModel).filter(active_incidents_clause()).order_by(IncidentModel.id).all():
        details = inc.details or {}
        if not details.get("investigation") or details.get("investigation_stale"):
            continue
        changes = _reconcile_changes(inc, alerts_by_id)
        for alert_id, change in changes:
            _mark_one(db, inc, alert_id, change, actor, withdraw_reason=f"evidence for this incident changed ({change})")
        if changes:
            marked.append(inc.id)
    return marked
