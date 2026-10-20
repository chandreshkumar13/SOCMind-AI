from datetime import datetime
from typing import Any, Optional
from pydantic import BaseModel


class AuditLogResponse(BaseModel):
    id: int
    timestamp: datetime
    actor: Optional[str] = None
    action: Optional[str] = None
    target_id: Optional[str] = None
    details: Any = None
