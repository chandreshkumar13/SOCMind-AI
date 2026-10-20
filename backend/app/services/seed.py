import os
import json
from typing import Dict, Any, List
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session
from app.models.models import AlertModel
from app.services.normalization import NormalizationService

DATASET_PATH = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "..", "..", "data", "sample_alerts", "synthetic_alerts.json")
)


def seed_synthetic_alerts(db: Session) -> Dict[str, Any]:
    """
    Reads synthetic alerts dataset and populates database idempotently.
    Prevents duplicate inserts when run multiple times.
    """
    if not os.path.exists(DATASET_PATH):
        return {"status": "error", "message": f"Dataset file not found at {DATASET_PATH}"}

    with open(DATASET_PATH, "r", encoding="utf-8") as f:
        raw_alerts: List[Dict[str, Any]] = json.load(f)

    inserted_count = 0
    skipped_count = 0

    for raw in raw_alerts:
        normalized = NormalizationService.normalize_alert(raw)
        alert_id = normalized["id"]
        external_id = normalized["external_alert_id"]

        # Check if alert already exists in DB
        existing = db.query(AlertModel).filter(
            (AlertModel.id == alert_id) | 
            ((AlertModel.external_alert_id == external_id) & (AlertModel.external_alert_id.isnot(None)))
        ).first()

        if existing:
            skipped_count += 1
            continue

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
        inserted_count += 1

    try:
        db.commit()
    except IntegrityError:
        # Another request seeded the same alerts at the same moment (e.g. a double-submitted call).
        db.rollback()
        return {"status": "success", "inserted": 0, "skipped": len(raw_alerts),
                "total_processed": len(raw_alerts), "note": "alerts were seeded concurrently"}

    return {
        "status": "success",
        "inserted": inserted_count,
        "skipped": skipped_count,
        "total_processed": len(raw_alerts)
    }
