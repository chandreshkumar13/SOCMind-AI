import json
from typing import List, Optional

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.models.models import AuditLogModel
from app.schemas.audit import AuditLogResponse

router = APIRouter()


def _to_response(row: AuditLogModel) -> AuditLogResponse:
    details = row.details
    if isinstance(details, str):
        try:
            details = json.loads(details)
        except ValueError:
            pass
    return AuditLogResponse(id=row.id, timestamp=row.timestamp, actor=row.actor, action=row.action,
                            target_id=row.target_id, details=details)


@router.get("/audit-logs", response_model=List[AuditLogResponse], summary="List Audit Log Entries")
def list_audit_logs(
    actor: Optional[str] = Query(None, description="Filter by actor (analyst name or agent name)"),
    action: Optional[str] = Query(None, description="Filter by action name"),
    target_id: Optional[str] = Query(None, description="Filter by alert or incident id"),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
):
    """Returns audit entries, newest first."""
    q = db.query(AuditLogModel)
    if actor:
        q = q.filter(AuditLogModel.actor == actor)
    if action:
        q = q.filter(AuditLogModel.action == action.upper())
    if target_id:
        q = q.filter(AuditLogModel.target_id == target_id)
    rows = q.order_by(AuditLogModel.id.desc()).offset(offset).limit(limit).all()
    return [_to_response(r) for r in rows]
