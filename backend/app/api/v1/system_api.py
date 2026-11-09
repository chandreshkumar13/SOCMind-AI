from typing import Any, Dict

from fastapi import APIRouter, Depends
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.core.config import EXECUTION_MODE, settings
from app.db.session import get_db
from app.models.models import AlertModel, AuditLogModel, IncidentModel
from app.services.incident_state import active_incidents_clause
from app.services.log_store import LOG_SOURCE_PATH
from app.services.threat_intel import api_key_configured, quota_snapshot, resolve_provider

router = APIRouter()


def _counts(db: Session, column, where=None) -> Dict[str, int]:
    query = db.query(column, func.count())
    if where is not None:
        query = query.filter(where)
    return {key or "UNKNOWN": n for key, n in query.group_by(column).all()}


@router.get("/stats", summary="Dashboard Statistics")
def stats(db: Session = Depends(get_db)) -> Dict[str, Any]:
    """True totals computed in the database (list endpoints are paginated, so counting their results would be wrong).
    Incidents are counted only while they are active: a merged incident is folded into another and is not counted."""
    active = active_incidents_clause()
    incident_status = _counts(db, IncidentModel.status, active)
    awaiting = (db.query(func.count(IncidentModel.id))
                .filter(active, IncidentModel.status == "RESPONSE_PROPOSED", IncidentModel.human_approval_status == "PENDING").scalar() or 0)
    return {
        "alerts": {"total": db.query(func.count(AlertModel.id)).scalar() or 0,
                   "by_severity": _counts(db, AlertModel.severity), "by_status": _counts(db, AlertModel.status)},
        "incidents": {"total": sum(incident_status.values()), "by_status": incident_status,
                      "by_severity": _counts(db, IncidentModel.severity, active),
                      "awaiting_human_review": awaiting},
        "audit_entries": db.query(func.count(AuditLogModel.id)).scalar() or 0,
    }


@router.get("/config", summary="Runtime Configuration (non-secret)")
def runtime_config() -> Dict[str, Any]:
    """What this backend is actually configured to do. Contains no secrets, keys or connection strings."""
    choice = resolve_provider()
    return {
        "version": settings.VERSION,
        "environment": settings.ENVIRONMENT,
        "database_engine": settings.DATABASE_URL.split(":")[0],
        "execution_mode": EXECUTION_MODE,
        "threat_intel": {
            "mode": {"mock": "mock", "virustotal": "live", "unavailable": "unavailable"}[choice.active],
            "requested_provider": choice.requested,
            "active_provider": choice.active,
            "live_provider_implemented": True,
            "live_provider_active": choice.active == "virustotal",
            "fallback_reason": choice.reason,
            "virustotal": {
                "api_key_configured": api_key_configured(),   # a yes/no only; the key itself is never returned
                "malicious_threshold": settings.VIRUSTOTAL_MALICIOUS_THRESHOLD,
                "max_lookups_per_alert": settings.VIRUSTOTAL_MAX_LOOKUPS_PER_ALERT,
                "requests_per_minute": settings.VIRUSTOTAL_REQUESTS_PER_MINUTE,
                "requests_per_day": settings.VIRUSTOTAL_REQUESTS_PER_DAY,
                "timeout_seconds": settings.VIRUSTOTAL_TIMEOUT_SECONDS,
                "cache_ttl_seconds": settings.VIRUSTOTAL_CACHE_TTL_SECONDS,
                "url_lookups": "disabled",
                "quota": quota_snapshot(),
            },
            "note": {
                "mock": "Reputation lookups use a local mock dataset and are not verified intelligence.",
                "virustotal": "Indicators are looked up on VirusTotal's public API. Results are third-party verdicts, not verified by SOCMind AI.",
                "unavailable": "No lookups are performed; IOCs are extracted only.",
            }[choice.active],
        },
        "llm": {"configured_provider": settings.LLM_PROVIDER, "used_by_agents": False,
                "note": "All five agents are deterministic rule-based code; no LLM is called."},
        "authentication": {"enabled": False,
                           "note": "The API has no authentication. Reviewer names are self-asserted. Do not expose it to untrusted networks."},
        "investigation_log_source": {"type": "synthetic_sample_file", "path": LOG_SOURCE_PATH},
        "sample_alert_dataset": "data/sample_alerts/synthetic_alerts.json",
    }
