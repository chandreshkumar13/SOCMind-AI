from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.models.models import AlertModel, IncidentModel
from app.schemas.incident import CorrelateRequest, IncidentDetailOut, IncidentOut, ReviewRequest
from app.services.incident_service import (
    DecisionError, correlate_and_store, investigate_incident, recommend_for_incident, review_incident, simulate_response,
)

router = APIRouter()


def _get_incident(db: Session, incident_id: str) -> IncidentModel:
    inc = db.query(IncidentModel).filter(IncidentModel.id == incident_id).first()
    if not inc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, f"Incident '{incident_id}' not found.")
    return inc


@router.get("/incidents", response_model=List[IncidentOut], summary="List Incidents")
def list_incidents(
    severity: Optional[str] = Query(None),
    incident_status: Optional[str] = Query(None, alias="status"),
    approval: Optional[str] = Query(None, description="PENDING, APPROVED or REJECTED"),
    limit: int = Query(50, ge=1, le=100),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
):
    q = db.query(IncidentModel)
    if severity:
        q = q.filter(IncidentModel.severity == severity.upper())
    if incident_status:
        q = q.filter(IncidentModel.status == incident_status.upper())
    if approval:
        q = q.filter(IncidentModel.human_approval_status == approval.upper())
    return q.order_by(IncidentModel.created_at.desc(), IncidentModel.id.desc()).offset(offset).limit(limit).all()


@router.get("/incidents/{incident_id}", response_model=IncidentDetailOut, summary="Get Incident Details")
def get_incident(incident_id: str, db: Session = Depends(get_db)):
    inc = _get_incident(db, incident_id)
    alerts = db.query(AlertModel).filter(AlertModel.id.in_(inc.correlated_alert_ids or [])).order_by(AlertModel.timestamp).all()
    out = IncidentDetailOut.model_validate(inc)
    out.alerts = alerts
    return out


@router.post("/incidents/correlate", summary="Correlate Alerts into Incidents")
def correlate(payload: Optional[CorrelateRequest] = None, db: Session = Depends(get_db)):
    """Groups non-closed alerts that share a host, IP or file hash within the time window into incidents."""
    return correlate_and_store(db, payload.window_hours if payload else 24)


@router.post("/incidents/{incident_id}/investigate", response_model=IncidentDetailOut, summary="Investigate an Incident")
def investigate(incident_id: str, db: Session = Depends(get_db)):
    """Builds the timeline and labelled findings (verified / mock_intel / hypothesis) for an incident."""
    inc = _get_incident(db, incident_id)
    investigate_incident(db, inc)
    return get_incident(incident_id, db)


@router.post("/incidents/{incident_id}/recommend", response_model=IncidentDetailOut, summary="Generate Response Recommendations")
def recommend(incident_id: str, db: Session = Depends(get_db)):
    """Generates evidence-based response proposals. Nothing is executed; a human must approve or reject."""
    inc = _get_incident(db, incident_id)
    try:
        recommend_for_incident(db, inc)
    except DecisionError as e:
        raise HTTPException(status.HTTP_409_CONFLICT, str(e))
    return get_incident(incident_id, db)


def _review(incident_id: str, decision: str, payload: ReviewRequest, db: Session):
    inc = _get_incident(db, incident_id)
    try:
        review_incident(db, inc, decision, payload.reviewer, payload.reason)
    except DecisionError as e:
        raise HTTPException(status.HTTP_409_CONFLICT, str(e))
    return get_incident(incident_id, db)


@router.post("/incidents/{incident_id}/approve", response_model=IncidentDetailOut, summary="Approve the Proposed Response")
def approve(incident_id: str, payload: ReviewRequest, db: Session = Depends(get_db)):
    """Records a human approval. The system only records the decision; it executes no action."""
    return _review(incident_id, "APPROVED", payload, db)


@router.post("/incidents/{incident_id}/reject", response_model=IncidentDetailOut, summary="Reject the Proposed Response")
def reject(incident_id: str, payload: ReviewRequest, db: Session = Depends(get_db)):
    return _review(incident_id, "REJECTED", payload, db)


@router.post("/incidents/{incident_id}/simulate", response_model=IncidentDetailOut, summary="Simulate the Approved Response")
def simulate(incident_id: str, payload: ReviewRequest, db: Session = Depends(get_db)):
    """Rehearses an APPROVED response. Nothing is executed: the system has no real response integration."""
    inc = _get_incident(db, incident_id)
    try:
        simulate_response(db, inc, payload.reviewer, payload.reason)
    except DecisionError as e:
        raise HTTPException(status.HTTP_409_CONFLICT, str(e))
    return get_incident(incident_id, db)
