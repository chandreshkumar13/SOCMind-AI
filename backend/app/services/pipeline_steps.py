"""Single-alert pipeline steps (triage, enrichment) shared by the REST endpoints.

Each step stores its result in alert.normalized_data, writes an audit entry and leaves the commit
to the caller, so the change and its audit record are saved in one transaction.
"""
from typing import Any, Dict

from sqlalchemy.orm import Session

from app.agents.enrichment.enrichment_agent import EnrichmentAgent
from app.agents.triage.triage_agent import TriageAgent
from app.models.models import AlertModel
from app.services.audit import log_action

# Statuses a triage / enrichment step may move forward from. Any other status (CLOSED, CORRELATED,
# ...) is left untouched: a closed alert is never re-opened and an alert is never moved backwards.
TRIAGE_FROM = ("NEW", "TRIAGED", "ENRICHED")
ENRICH_FROM = ("NEW", "TRIAGED", "ENRICHED")

INTEL_DISCLAIMER = (
    "Results come from LOCAL MOCK threat intelligence, not a verified live feed. "
    "A CLEAN or UNKNOWN reputation only means the mock has no malicious record; "
    "it does not mean the indicator is verified safe."
)


def alert_dict(alert: AlertModel) -> Dict[str, Any]:
    """Flat dictionary view of an alert record, as consumed by the agents."""
    return {
        "id": alert.id,
        "external_alert_id": alert.external_alert_id,
        "timestamp": alert.timestamp.isoformat() if alert.timestamp else None,
        "source": alert.source,
        "alert_title": alert.alert_title,
        "description": alert.description,
        "severity": alert.severity,
        "host": alert.host,
        "username": alert.username,
        "source_ip": alert.source_ip,
        "destination_ip": alert.destination_ip,
        "file_hash": alert.file_hash,
        "command_line": alert.command_line,
        "status": alert.status,
    }


def triage_alert_record(db: Session, alert: AlertModel) -> Dict[str, Any]:
    """Runs triage and stores the result in normalized_data['triage']. Caller commits."""
    result = TriageAgent().analyze_alert(alert_dict(alert))
    data = dict(alert.normalized_data or {})
    data["triage"] = result
    alert.normalized_data = data
    if alert.status in TRIAGE_FROM:
        alert.status = "TRIAGED"
    log_action(db, "Triage Agent", "ALERT_TRIAGED", alert.id,
               {"suspicion_score": result["suspicion_score"], "priority": result["priority"]})
    return result


def enrich_alert_record(db: Session, alert: AlertModel) -> Dict[str, Any]:
    """Runs IOC extraction + mock enrichment and stores it in normalized_data['enrichment']. Caller commits.

    The enrichment result keeps the EnrichmentAgent contract (total_iocs_extracted, summary, iocs);
    only the additive provenance keys intel_mode / verified / disclaimer are attached here.
    """
    agent = EnrichmentAgent(mock_mode=True)
    result = agent.enrich_alert(alert_dict(alert))
    result["intel_mode"] = "mock"
    result["verified"] = False
    result["disclaimer"] = INTEL_DISCLAIMER
    data = dict(alert.normalized_data or {})
    data["enrichment"] = result
    alert.normalized_data = data
    if alert.status in ENRICH_FROM:
        alert.status = "ENRICHED"
    log_action(db, agent.agent_name, "ALERT_ENRICHED", alert.id,
               {"total_iocs_extracted": result["total_iocs_extracted"], "summary": result["summary"],
                "intel_mode": "mock"})
    return result
