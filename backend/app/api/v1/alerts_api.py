from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session
from sqlalchemy import or_

from app.db.session import get_db
from app.models.models import AlertModel
from app.schemas.alert import (
    AlertIngestRequest, 
    AlertResponse, 
    PaginatedAlertResponse, 
    AlertUpdateStatus,
    TriageResultResponse,
    AlertTriageResponse
)
from app.services.normalization import NormalizationService
from app.services.seed import seed_synthetic_alerts
from app.services.audit import log_action
from app.services.pipeline_steps import triage_alert_record, enrich_alert_record

router = APIRouter()


@router.post("/alerts", response_model=AlertResponse, status_code=status.HTTP_201_CREATED, summary="Ingest Security Alert")
def ingest_alert(payload: AlertIngestRequest, db: Session = Depends(get_db)):
    """
    Ingests a raw or semi-structured security alert, normalizes fields deterministically,
    and persists record to the database.
    """
    raw_dict = payload.model_dump(exclude_unset=True)
    normalized = NormalizationService.normalize_alert(raw_dict)

    # Check for existing alert with same ID
    existing = db.query(AlertModel).filter(AlertModel.id == normalized["id"]).first()
    if existing:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Alert with ID {normalized['id']} already exists."
        )

    alert_record = AlertModel(
        id=normalized["id"],
        external_alert_id=normalized["external_alert_id"],
        timestamp=normalized["timestamp"],
        source=normalized["source"],
        alert_title=normalized["alert_title"],
        description=normalized["description"],
        severity=normalized["severity"],
        host=normalized["host"],
        username=normalized["username"],
        source_ip=normalized["source_ip"],
        destination_ip=normalized["destination_ip"],
        file_hash=normalized["file_hash"],
        command_line=normalized["command_line"],
        status=normalized["status"],
        normalized_data=normalized["normalized_data"]
    )

    db.add(alert_record)
    log_action(db, "API", "ALERT_INGESTED", normalized["id"],
               {"source": normalized["source"], "severity": normalized["severity"]})
    db.commit()
    db.refresh(alert_record)

    return alert_record


@router.get("/alerts", response_model=List[AlertResponse], summary="List Ingested Security Alerts")
def list_alerts(
    severity: Optional[str] = Query(None, description="Filter by severity (CRITICAL, HIGH, MEDIUM, LOW, INFO)"),
    status: Optional[str] = Query(None, description="Filter by status (NEW, TRIAGED, CORRELATED, CLOSED)"),
    source: Optional[str] = Query(None, description="Filter by security source system"),
    search: Optional[str] = Query(None, description="Search term for title, description, host, user, IP"),
    limit: int = Query(50, ge=1, le=100, description="Max items to return"),
    offset: int = Query(0, ge=0, description="Pagination offset"),
    db: Session = Depends(get_db)
):
    """
    Returns list of normalized security alerts from the database with filtering & search.
    """
    query = db.query(AlertModel)

    if severity:
        query = query.filter(AlertModel.severity == severity.upper())

    if status:
        query = query.filter(AlertModel.status == status.upper())

    if source:
        query = query.filter(AlertModel.source.ilike(f"%{source}%"))

    if search:
        search_term = f"%{search}%"
        query = query.filter(
            or_(
                AlertModel.alert_title.ilike(search_term),
                AlertModel.description.ilike(search_term),
                AlertModel.host.ilike(search_term),
                AlertModel.username.ilike(search_term),
                AlertModel.source_ip.ilike(search_term),
                AlertModel.destination_ip.ilike(search_term)
            )
        )

    alerts = query.order_by(AlertModel.timestamp.desc()).offset(offset).limit(limit).all()
    return alerts


@router.get("/alerts/{alert_id}", response_model=AlertResponse, summary="Get Alert Details")
def get_alert_by_id(alert_id: str, db: Session = Depends(get_db)):
    """
    Returns full details for a specific normalized alert.
    """
    alert = db.query(AlertModel).filter(AlertModel.id == alert_id).first()
    if not alert:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Alert with ID '{alert_id}' not found."
        )
    return alert


@router.post("/alerts/{alert_id}/triage", response_model=AlertTriageResponse, summary="Triage an Existing Alert")
def triage_alert(alert_id: str, db: Session = Depends(get_db)):
    """
    Runs deterministic TriageAgent on an existing alert, persists triage rationale/score,
    and updates alert status to TRIAGED.
    """
    alert = db.query(AlertModel).filter(AlertModel.id == alert_id).first()
    if not alert:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Alert with ID '{alert_id}' not found."
        )

    # Stores the triage result and audits it. A CLOSED alert keeps its status (it is never re-opened).
    triage_result = triage_alert_record(db, alert)

    db.commit()
    db.refresh(alert)

    return {
        "alert": alert,
        "triage_result": triage_result
    }


@router.post("/alerts/{alert_id}/enrich", summary="Enrich Alert with IOC Threat Intelligence (Phase 3.2)")
def enrich_alert(alert_id: str, db: Session = Depends(get_db)):
    """
    Phase 3.2 — IOC Extraction & Threat Intelligence Enrichment.

    Extracts all Indicators of Compromise (IPs, hashes, domains, URLs) from
    the stored alert's structured and free-text fields, queries mock threat
    intelligence, and persists the enrichment result.
    """
    alert = db.query(AlertModel).filter(AlertModel.id == alert_id).first()
    if not alert:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Alert with ID '{alert_id}' not found."
        )

    # Stores the enrichment result and audits it. A CLOSED alert keeps its status.
    enrichment_result = enrich_alert_record(db, alert)

    db.commit()
    db.refresh(alert)

    return {
        "alert": alert,
        "enrichment_result": enrichment_result
    }


@router.delete("/alerts/{alert_id}", summary="Close or Remove Alert")
def delete_alert(alert_id: str, db: Session = Depends(get_db)):
    """
    Marks an alert status as CLOSED (safe alternative to hard deletion).
    """
    alert = db.query(AlertModel).filter(AlertModel.id == alert_id).first()
    if not alert:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Alert with ID '{alert_id}' not found."
        )

    alert.status = "CLOSED"
    log_action(db, "API", "ALERT_CLOSED", alert_id)
    db.commit()

    return {
        "status": "success",
        "message": f"Alert '{alert_id}' has been marked as CLOSED.",
        "alert_id": alert_id
    }


@router.post("/alerts/seed", summary="Seed Synthetic Alerts into Database")
def seed_alerts(db: Session = Depends(get_db)):
    """
    Populates database with 10 synthetic test alerts. Idempotent check prevents duplicates.
    """
    result = seed_synthetic_alerts(db)
    if result.get("status") == "success" and result.get("inserted"):
        log_action(db, "API", "ALERTS_SEEDED", "synthetic_alerts.json", result)
        db.commit()
    return result
