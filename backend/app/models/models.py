from datetime import datetime
from sqlalchemy import Column, String, Integer, DateTime, Text, JSON, Boolean
from app.models.base import Base


class AlertModel(Base):
    __tablename__ = "alerts"

    id = Column(String, primary_key=True, index=True)
    external_alert_id = Column(String, index=True, nullable=True)
    timestamp = Column(DateTime, default=datetime.utcnow)
    source = Column(String, index=True)
    alert_title = Column(String)
    description = Column(Text, nullable=True)
    severity = Column(String, index=True, default="MEDIUM")  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    host = Column(String, nullable=True, index=True)
    username = Column(String, nullable=True)
    source_ip = Column(String, nullable=True)
    destination_ip = Column(String, nullable=True)
    file_hash = Column(String, nullable=True)
    command_line = Column(Text, nullable=True)
    status = Column(String, default="NEW", index=True)  # NEW, TRIAGED, CORRELATED, CLOSED
    normalized_data = Column(JSON, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class IncidentModel(Base):
    __tablename__ = "incidents"

    id = Column(String, primary_key=True, index=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    title = Column(String)
    severity = Column(String)
    status = Column(String, default="OPEN")
    correlated_alert_ids = Column(JSON)  # List of alert IDs
    ai_summary = Column(Text, nullable=True)
    recommended_action = Column(String, nullable=True)
    human_approval_status = Column(String, default="PENDING")  # PENDING, APPROVED, REJECTED
    # Structured analysis: correlation evidence, investigation timeline/findings, recommendations, review decision
    details = Column(JSON, nullable=True)


class AuditLogModel(Base):
    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True, autoincrement=True)
    timestamp = Column(DateTime, default=datetime.utcnow)
    actor = Column(String)  # Analyst name or Agent name
    action = Column(String)
    target_id = Column(String)
    details = Column(Text)
