from typing import Any, Optional
from pydantic import BaseModel

from app.schemas.common import UTCDateTime


class AuditLogResponse(BaseModel):
    id: int
    timestamp: UTCDateTime
    actor: Optional[str] = None
    action: Optional[str] = None
    target_id: Optional[str] = None
    details: Any = None
