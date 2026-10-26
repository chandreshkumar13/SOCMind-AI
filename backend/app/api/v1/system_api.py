from typing import Any, Dict

from fastapi import APIRouter, Depends
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.core.config import EXECUTION_MODE, settings
from app.db.session import get_db
from app.models.models import AlertModel, AuditLogModel, IncidentModel
from app.services.log_store import LOG_SOURCE_PATH

router = APIRouter()


def _counts(db: Session, column) -> Dict[str, int]:
    return {key or "UNKNOWN": n for key, n in db.query(column, func.count()).group_by(column).all()}


@router.get("/stats", summary="Dashboard Statistics")
def stats(db: Session = Depends(get_db)) -> Dict[str, Any]:
    """True totals computed in the database (list endpoints are paginated, so counting their results would be wrong)."""
    incident_status = _counts(db, IncidentModel.status)
    open_incidents = {k: v for k, v in incident_status.items() if k != "MERGED"}
    awaiting = (db.query(func.count(IncidentModel.id))
                .filter(IncidentModel.status == "RESPONSE_PROPOSED", IncidentModel.human_approval_status == "PENDING").scalar() or 0)
    return {
        "alerts": {"total": db.query(func.count(AlertModel.id)).scalar() or 0,
                   "by_severity": _counts(db, AlertModel.severity), "by_status": _counts(db, AlertModel.status)},
        "incidents": {"total": sum(open_incidents.values()), "by_status": open_incidents,
                      "by_severity": {k: v for k, v in _counts(db, IncidentModel.severity).items()},
                      "awaiting_human_review": awaiting},
        "audit_entries": db.query(func.count(AuditLogModel.id)).scalar() or 0,
    }


@router.get("/config", summary="Runtime Configuration (non-secret)")
def runtime_config() -> Dict[str, Any]:
    """What this backend is actually configured to do. Contains no secrets, keys or connection strings."""
    return {
        "version": settings.VERSION,
        "environment": settings.ENVIRONMENT,
        "database_engine": settings.DATABASE_URL.split(":")[0],
        "execution_mode": EXECUTION_MODE,
        "threat_intel": {
            "mode": "mock" if settings.THREAT_INTEL_MOCK_MODE else "unavailable",
            "live_provider_implemented": False,
            "note": ("Reputation lookups use a local mock dataset and are not verified intelligence."
                     if settings.THREAT_INTEL_MOCK_MODE else "No lookups are performed; IOCs are extracted only."),
        },
        "llm": {"configured_provider": settings.LLM_PROVIDER, "used_by_agents": False,
                "note": "All five agents are deterministic rule-based code; no LLM is called."},
        "authentication": {"enabled": False,
                           "note": "The API has no authentication. Reviewer names are self-asserted. Do not expose it to untrusted networks."},
        "investigation_log_source": {"type": "synthetic_sample_file", "path": LOG_SOURCE_PATH},
        "sample_alert_dataset": "data/sample_alerts/synthetic_alerts.json",
    }
