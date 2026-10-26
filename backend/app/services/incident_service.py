"""Persistence logic that turns correlation groups into incident records."""
import copy
from datetime import datetime
from typing import Any, Dict, List

from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.agents.correlation.correlation_agent import CorrelationAgent, SEVERITY_ORDER
from app.models.models import AlertModel, IncidentModel
from app.services.audit import log_action
from app.services.pipeline_steps import alert_dict

# Alert statuses an incident step may move forward from (never CLOSED, never backwards)
CORRELATE_FROM = ("NEW", "TRIAGED", "ENRICHED")
INVESTIGATE_FROM = ("NEW", "TRIAGED", "ENRICHED", "CORRELATED")


def _now_iso() -> str:
    return datetime.utcnow().isoformat() + "Z"


def _details(incident: IncidentModel) -> Dict[str, Any]:
    """Deep copy of incident.details, so nested edits are always detected as a change when saved."""
    return copy.deepcopy(incident.details or {})


def next_incident_id(db: Session) -> str:
    prefix = f"INC-{datetime.utcnow().year}-"
    numbers = []
    for (iid,) in db.query(IncidentModel.id).filter(IncidentModel.id.like(prefix + "%")).all():
        try:
            numbers.append(int(iid.rsplit("-", 1)[1]))
        except ValueError:
            pass
    return f"{prefix}{(max(numbers) + 1 if numbers else 1):03d}"


def _incident_title(group: Dict[str, Any]) -> str:
    host = group.get("primary_host") or "multiple hosts"
    more = group["alert_count"] - 1
    return f"{group['top_alert_title']} (+{more} related alert{'s' if more != 1 else ''}) on {host}"


def correlate_and_store(db: Session, window_hours: int = 24) -> Dict[str, Any]:
    """Correlates all non-closed alerts and creates/updates incidents. Idempotent.

    Two requests running at the same moment can pick the same new incident id; the database
    rejects the second insert, so the whole step is rolled back and repeated once on the fresh state.
    """
    try:
        return _correlate_once(db, window_hours)
    except IntegrityError:
        db.rollback()
        return _correlate_once(db, window_hours)
    except Exception:
        db.rollback()
        raise


def _correlate_once(db: Session, window_hours: int) -> Dict[str, Any]:
    alerts = db.query(AlertModel).filter(AlertModel.status != "CLOSED").all()
    by_id = {a.id: a for a in alerts}
    agent = CorrelationAgent()
    groups = agent.correlate_alerts([alert_dict(a) for a in alerts], window_hours=window_hours)
    skipped = agent.last_skipped["no_valid_timestamp"]

    created: List[str] = []
    updated: List[str] = []
    unchanged: List[str] = []
    for group in groups:
        ids = set(group["alert_ids"])
        overlapping = [i for i in db.query(IncidentModel).filter(IncidentModel.status != "MERGED").order_by(IncidentModel.id).all()
                       if ids & set(i.correlated_alert_ids or [])]
        correlation_info = {k: group[k] for k in ("shared_entities", "reasons", "confidence", "first_seen", "last_seen", "alert_count")}
        correlation_info["window_hours"] = window_hours
        if not overlapping:
            inc = IncidentModel(
                id=next_incident_id(db), title=_incident_title(group), severity=group["severity"], status="OPEN",
                correlated_alert_ids=group["alert_ids"], human_approval_status="PENDING",
                details={"correlation": correlation_info, "investigation_stale": True, "recommendations_stale": True},
            )
            db.add(inc)
            db.flush()
            log_action(db, agent.agent_name, "INCIDENT_CREATED", inc.id,
                       {"alert_ids": group["alert_ids"], "confidence": group["confidence"], "reasons": group["reasons"]})
            created.append(inc.id)
            target = inc
        else:
            target = overlapping[0]
            merged_ids = sorted(ids | set(target.correlated_alert_ids or []))
            for other in overlapping[1:]:
                merged_ids = sorted(set(merged_ids) | set(other.correlated_alert_ids or []))
                other.status = "MERGED"
                other_details = _details(other)
                other_details["merged_into"] = target.id
                other.details = other_details
                log_action(db, agent.agent_name, "INCIDENT_MERGED", other.id, {"merged_into": target.id})
            if merged_ids == sorted(target.correlated_alert_ids or []) and len(overlapping) == 1:
                unchanged.append(target.id)
                continue
            target.correlated_alert_ids = merged_ids
            top = max((by_id[i] for i in merged_ids if i in by_id), key=lambda a: SEVERITY_ORDER.get(a.severity, 0), default=None)
            if top:
                target.severity = top.severity
            group["alert_ids"], group["alert_count"] = merged_ids, len(merged_ids)
            target.title = _incident_title(group)
            target_details = _details(target)
            target_details.update({"correlation": correlation_info, "investigation_stale": True, "recommendations_stale": True})
            if target.human_approval_status != "PENDING":
                # The old decision no longer applies; keep it as history rather than showing it as current
                target_details.setdefault("review_history", []).append(
                    {"review": target_details.pop("review", None), "simulation": target_details.pop("simulation", None),
                     "superseded_at": _now_iso()})
            target.details = target_details
            if target.human_approval_status != "PENDING":
                log_action(db, agent.agent_name, "APPROVAL_RESET", target.id,
                           {"reason": "new correlated alerts changed the incident after a decision", "previous": target.human_approval_status})
                target.human_approval_status = "PENDING"
                target.status = "OPEN"
            log_action(db, agent.agent_name, "INCIDENT_UPDATED", target.id, {"alert_ids": merged_ids})
            updated.append(target.id)
        for aid in target.correlated_alert_ids:
            al = by_id.get(aid)
            if al is not None:
                data = dict(al.normalized_data or {})
                data["incident_id"] = target.id
                al.normalized_data = data
                if al.status in CORRELATE_FROM:
                    al.status = "CORRELATED"
    db.commit()
    return {
        "alerts_considered": len(alerts), "groups_found": len(groups),
        "created": created, "updated": updated, "unchanged": unchanged,
        "alerts_without_valid_timestamp": skipped,
        "message": ("Incidents created/updated from correlated alerts." if groups else
                    "Insufficient correlation evidence: no alerts share a host, IP or file hash within the time window."),
    }


def investigate_incident(db: Session, incident: IncidentModel) -> Dict[str, Any]:
    """Runs the Investigation Agent on an incident and stores timeline/findings in incident.details."""
    from app.agents.investigation.investigation_agent import InvestigationAgent
    from app.services.log_store import LOG_SOURCE_PATH, load_sample_logs

    alerts = db.query(AlertModel).filter(AlertModel.id.in_(incident.correlated_alert_ids or [])).all()
    agent = InvestigationAgent()
    details = _details(incident)
    logs = load_sample_logs()
    result = agent.investigate({"id": incident.id, "title": incident.title, "severity": incident.severity,
                                "correlation": details.get("correlation")},
                               [alert_dict(a) for a in alerts], logs)
    result["log_source"] = {"type": "synthetic_sample_file", "path": LOG_SOURCE_PATH, "records_available": len(logs),
                            "note": "Logs come from a bundled synthetic sample file; no SIEM or log platform was queried."}
    details["investigation"] = result
    details["investigation_stale"] = False
    details["recommendations_stale"] = True
    incident.details = details
    incident.ai_summary = result["summary"]
    if incident.status in ("OPEN", "INVESTIGATED"):
        incident.status = "INVESTIGATED"
    for a in alerts:
        if a.status in INVESTIGATE_FROM:
            a.status = "INVESTIGATING"
    log_action(db, agent.agent_name, "INCIDENT_INVESTIGATED", incident.id,
               {"timeline_events": len(result["timeline"]), "findings": len(result["findings"]),
                "evidence_strength": result["evidence_strength"]})
    db.commit()
    return result


class DecisionError(Exception):
    """Raised when a review decision is not allowed (mapped to HTTP 409)."""


def recommend_for_incident(db: Session, incident: IncidentModel) -> Dict[str, Any]:
    """Runs the Response Agent (investigating first if needed) and stores recommendations."""
    from app.agents.response.response_agent import ResponseAgent

    if incident.human_approval_status != "PENDING":
        raise DecisionError("A human decision is already recorded; recommendations can no longer be regenerated.")
    details = _details(incident)
    if not details.get("investigation") or details.get("investigation_stale"):
        investigate_incident(db, incident)
        details = _details(incident)
    alerts = db.query(AlertModel).filter(AlertModel.id.in_(incident.correlated_alert_ids or [])).all()
    agent = ResponseAgent()
    result = agent.recommend({"id": incident.id, "severity": incident.severity}, [alert_dict(a) for a in alerts], details.get("investigation"))
    details["recommendations"] = result["recommendations"]
    details["response"] = {k: result[k] for k in ("evidence_strength", "requires_human_approval", "execution_mode", "max_impact", "note", "context")}
    details["recommendations_stale"] = False
    incident.details = details
    incident.recommended_action = result["primary_action"]
    incident.status = "RESPONSE_PROPOSED"
    log_action(db, agent.agent_name, "RESPONSE_RECOMMENDED", incident.id,
               {"recommendations": len(result["recommendations"]), "primary_action": result["primary_action"], "max_impact": result["max_impact"]})
    db.commit()
    return result


def review_incident(db: Session, incident: IncidentModel, decision: str, reviewer: str, reason: str = None) -> IncidentModel:
    """Records a human APPROVED/REJECTED decision. No action is executed."""
    details = _details(incident)
    recs = details.get("recommendations")
    if not recs:
        raise DecisionError("There is no recommendation to review; run the recommendation step first.")
    if details.get("recommendations_stale"):
        raise DecisionError("The recommendation is out of date because the incident changed; regenerate it first.")
    if incident.human_approval_status != "PENDING":
        raise DecisionError(f"A decision ({incident.human_approval_status}) is already recorded for this incident.")
    # Claim the decision atomically: if a concurrent request decided first, this UPDATE matches no row
    claimed = (db.query(IncidentModel)
               .filter(IncidentModel.id == incident.id, IncidentModel.human_approval_status == "PENDING")
               .update({"human_approval_status": decision}, synchronize_session=False))
    if claimed != 1:
        db.rollback()
        raise DecisionError("A decision was recorded by someone else at the same moment; reload the incident.")
    for r in recs:
        r["status"] = decision
    details["recommendations"] = recs
    details["review"] = {"decision": decision, "reviewer": reviewer, "reason": reason,
                         "reviewed_at": _now_iso(),
                         "execution": "simulation_only: no action was executed by SOCMind AI"}
    incident.details = details
    incident.human_approval_status = decision
    incident.status = f"RESPONSE_{decision}"
    log_action(db, reviewer, f"INCIDENT_{decision}", incident.id, {"reason": reason, "recommendations": [r["action"] for r in recs]})
    db.commit()
    return incident


def simulate_response(db: Session, incident: IncidentModel, actor: str, reason: str = None) -> IncidentModel:
    """Records a SIMULATION of an approved response. Nothing is executed and no system is touched.

    APPROVED means "a human agreed to the proposal"; SIMULATED means "the workflow was rehearsed". There is no
    state meaning EXECUTED because SOCMind AI has no real response integration.
    """
    details = _details(incident)
    recs = details.get("recommendations") or []
    if incident.human_approval_status != "APPROVED":
        raise DecisionError(f"Only an approved response can be simulated (current decision: {incident.human_approval_status}).")
    if details.get("recommendations_stale") or not recs:
        raise DecisionError("The approved recommendations are out of date; regenerate and re-approve them first.")
    if details.get("simulation") or incident.status == "RESPONSE_SIMULATED":
        raise DecisionError("This approved response was already simulated.")
    claimed = (db.query(IncidentModel)
               .filter(IncidentModel.id == incident.id, IncidentModel.status == "RESPONSE_APPROVED")
               .update({"status": "RESPONSE_SIMULATED"}, synchronize_session=False))
    if claimed != 1:
        db.rollback()
        raise DecisionError("The incident changed at the same moment; reload it and try again.")
    for r in recs:
        r["simulation_status"] = "SIMULATED"
        r["executed"] = False
    details["recommendations"] = recs
    details["simulation"] = {
        "mode": "simulation", "status": "SIMULATED", "simulated_by": actor, "reason": reason, "simulated_at": _now_iso(),
        "actions": [{"id": r["id"], "action": r["action"], "outcome": "Simulated only. No command was run and no system was changed."}
                    for r in recs],
        "note": "SOCMind AI has no real response integration. Carry out approved actions manually through your own change process.",
    }
    incident.details = details
    incident.status = "RESPONSE_SIMULATED"
    log_action(db, actor, "RESPONSE_SIMULATED", incident.id,
               {"reason": reason, "actions": [r["action"] for r in recs], "executed": False})
    db.commit()
    return incident
