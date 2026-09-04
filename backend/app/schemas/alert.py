from datetime import datetime
from typing import Optional, Any, Dict, List
from pydantic import BaseModel, ConfigDict, Field


class AlertIngestRequest(BaseModel):
    """
    Schema for ingesting raw/semi-structured security alerts via POST /api/v1/alerts.
    """
    alert_title: Optional[str] = Field(None, description="Title or name of the alert")
    alert_name: Optional[str] = Field(None, description="Alternative field name for alert title")
    source: Optional[str] = Field(None, description="Source security system (Splunk, CrowdStrike, Defender, etc.)")
    source_system: Optional[str] = Field(None, description="Alternative field name for source")
    severity: Optional[str] = Field(None, description="Alert severity (CRITICAL, HIGH, MEDIUM, LOW, INFO)")
    raw_severity: Optional[str] = Field(None, description="Raw severity from source system")
    timestamp: Optional[str] = Field(None, description="Event ISO timestamp")
    description: Optional[str] = Field(None, description="Detailed alert description")
    host: Optional[str] = Field(None, description="Target host name")
    host_name: Optional[str] = Field(None, description="Alternative field name for host")
    username: Optional[str] = Field(None, description="Associated user name")
    user: Optional[str] = Field(None, description="Alternative field name for user")
    source_ip: Optional[str] = Field(None, description="Source IP address")
    ip_address: Optional[str] = Field(None, description="Alternative field name for source IP")
    destination_ip: Optional[str] = Field(None, description="Destination IP address")
    file_hash: Optional[str] = Field(None, description="Associated binary file hash (SHA256/MD5)")
    command_line: Optional[str] = Field(None, description="Executed command line string (DATA ONLY)")
    external_alert_id: Optional[str] = Field(None, description="ID from upstream SIEM/EDR")

    model_config = ConfigDict(extra="allow")


class AlertResponse(BaseModel):
    """
    Normalized Alert response schema returned by backend endpoints.
    """
    id: str
    external_alert_id: Optional[str] = None
    timestamp: datetime
    source: str
    alert_title: str
    description: Optional[str] = None
    severity: str
    host: Optional[str] = None
    username: Optional[str] = None
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    file_hash: Optional[str] = None
    command_line: Optional[str] = None
    status: str
    normalized_data: Optional[Dict[str, Any]] = None
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class AlertUpdateStatus(BaseModel):
    """
    Schema for updating alert status.
    """
    status: str = Field(..., description="New status: NEW, TRIAGED, CORRELATED, CLOSED")


class PaginatedAlertResponse(BaseModel):
    """
    Paginated alert list response container.
    """
    total: int
    items: List[AlertResponse]
    page: int
    limit: int
