import json
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.models.models import AuditLogModel
from app.services.orchestrator import PipelineBusy, PipelineOrchestrator, UnknownAlerts

router = APIRouter()

AGENTS = [
    ("Triage Agent", "Deterministic, explainable suspicion scoring"),
    ("Enrichment Agent", "IOC extraction and (mock) threat-intelligence enrichment"),
    ("Correlation Agent", "Groups related alerts into incidents"),
    ("Investigation Agent", "Timeline and labelled findings (verified / mock intel / hypothesis)"),
    ("Response Agent", "Evidence-based response proposals; human approval required"),
]


class PipelineRunRequest(BaseModel):
    alert_ids: Optional[List[str]] = Field(None, description="Limit triage/enrichment to these alerts")
    window_hours: int = Field(24, ge=1, le=168)


@router.post("/pipeline/run", summary="Run the Multi-Agent Pipeline")
def run_pipeline(payload: Optional[PipelineRunRequest] = None, db: Session = Depends(get_db)):
    """
    Triage -> Enrichment -> Correlation -> Investigation -> Response recommendation.
    Idempotent and fault tolerant. Human approval is a separate step.
    `outcome` is success / partial / failure; 404 if none of `alert_ids` exist; 409 if a run is already in progress.
    """
    payload = payload or PipelineRunRequest()
    try:
        return PipelineOrchestrator().run(db, payload.alert_ids, payload.window_hours)
    except PipelineBusy as e:
        raise HTTPException(status.HTTP_409_CONFLICT, str(e))
    except UnknownAlerts as e:
        raise HTTPException(status.HTTP_404_NOT_FOUND, str(e))


@router.get("/pipeline/runs", summary="Recent Pipeline Runs")
def list_runs(limit: int = Query(10, ge=1, le=50), db: Session = Depends(get_db)) -> List[Dict[str, Any]]:
    rows = db.query(AuditLogModel).filter(AuditLogModel.action == "PIPELINE_RUN").order_by(AuditLogModel.id.desc()).limit(limit).all()
    out = []
    for r in rows:
        try:
            out.append(json.loads(r.details))
        except (TypeError, ValueError):
            continue
    return out


@router.get("/agents", summary="Agent Status and Activity")
def agent_status(db: Session = Depends(get_db)) -> List[Dict[str, Any]]:
    """Per-agent activity derived from the audit log (real counts, not static text)."""
    result = []
    for name, role in AGENTS + [("Orchestrator", "Coordinates the five agents")]:
        total = db.query(func.count(AuditLogModel.id)).filter(AuditLogModel.actor == name).scalar() or 0
        last = db.query(AuditLogModel).filter(AuditLogModel.actor == name).order_by(AuditLogModel.id.desc()).first()
        failures = db.query(func.count(AuditLogModel.id)).filter(AuditLogModel.actor == name, AuditLogModel.action == "AGENT_FAILED").scalar() or 0
        result.append({"name": name, "role": role, "status": "READY", "total_actions": total, "failures": failures,
                       "last_action": last.action if last else None, "last_target": last.target_id if last else None,
                       "last_run_at": last.timestamp.isoformat() if last else None})
    return result
