from datetime import datetime
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, ConfigDict, Field

from app.schemas.alert import AlertResponse


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


class IncidentOut(BaseModel):
    """Incident as returned by the incidents API (real datetimes, structured details)."""
    id: str
    created_at: datetime
    title: str
    severity: str
    status: str
    correlated_alert_ids: List[str]
    ai_summary: Optional[str] = None
    recommended_action: Optional[str] = None
    human_approval_status: str
    details: Optional[Dict[str, Any]] = None

    model_config = ConfigDict(from_attributes=True)


class IncidentDetailOut(IncidentOut):
    alerts: List[AlertResponse] = []


class CorrelateRequest(BaseModel):
    window_hours: int = Field(24, ge=1, le=168, description="Maximum gap between linked alerts, in hours")


class ReviewRequest(BaseModel):
    """Human review decision for an incident's proposed response."""
    reviewer: str = Field(..., min_length=1, max_length=100, description="Name of the analyst making the decision")
    reason: Optional[str] = Field(None, max_length=500)
