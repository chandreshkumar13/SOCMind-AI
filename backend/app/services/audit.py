"""Audit logging helper.

Every significant action (by an API call, an agent or a human reviewer) is recorded in the
audit_logs table. The helper only adds the row to the session; the caller commits, so the audit
entry and the change it describes are saved in the same transaction.
"""
import json
from typing import Any, Optional

from sqlalchemy.orm import Session

from app.models.models import AuditLogModel


def log_action(db: Session, actor: str, action: str, target_id: Optional[str], details: Any = None) -> AuditLogModel:
    entry = AuditLogModel(
        actor=actor,
        action=action,
        target_id=str(target_id) if target_id is not None else None,
        details=json.dumps(details, default=str) if details is not None else None,
    )
    db.add(entry)
    return entry
