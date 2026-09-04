from typing import List, Optional
from pydantic import BaseModel, ConfigDict


class IncidentBase(BaseModel):
    id: str
    created_at: str
    title: str
    severity: str
    status: str = "Open"
    correlated_alert_ids: List[str]
    ai_summary: Optional[str] = None
    recommended_action: Optional[str] = None
    human_approval_status: str = "Pending"

    model_config = ConfigDict(from_attributes=True)


class IncidentCreate(IncidentBase):
    pass


class IncidentResponse(IncidentBase):
    pass
