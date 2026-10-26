import re
import uuid
from datetime import datetime, timezone
from typing import Dict, Any, Optional

# Severity mapping table
SEVERITY_MAP = {
    "critical": "CRITICAL",
    "catastrophic": "CRITICAL",
    "1": "CRITICAL",
    "10": "CRITICAL",
    "9": "CRITICAL",
    "high": "HIGH",
    "severe": "HIGH",
    "2": "HIGH",
    "8": "HIGH",
    "7": "HIGH",
    "medium": "MEDIUM",
    "moderate": "MEDIUM",
    "3": "MEDIUM",
    "5": "MEDIUM",
    "6": "MEDIUM",
    "low": "LOW",
    "minor": "LOW",
    "4": "LOW",
    "info": "INFO",
    "informational": "INFO",
    "0": "INFO"
}

# Status mapping table
STATUS_MAP = {
    "new": "NEW",
    "triaged": "TRIAGED",
    "correlated": "CORRELATED",
    "closed": "CLOSED"
}


class NormalizationService:
    """
    Deterministic Alert Normalization Engine.
    Converts raw SIEM, EDR, Firewall, and Cloud security alerts into a
    unified internal schema without using non-deterministic LLM calls.
    """

    @staticmethod
    def normalize_severity(raw_severity: Optional[str]) -> str:
        if not raw_severity:
            return "MEDIUM"
        cleaned = str(raw_severity).strip().lower()
        return SEVERITY_MAP.get(cleaned, "MEDIUM")

    @staticmethod
    def normalize_status(raw_status: Optional[str]) -> str:
        if not raw_status:
            return "NEW"
        cleaned = str(raw_status).strip().lower()
        return STATUS_MAP.get(cleaned, "NEW")

    @staticmethod
    def normalize_source(raw_source: Optional[str]) -> str:
        if not raw_source:
            return "Generic SIEM"
        src = str(raw_source).strip()
        src_lower = src.lower()

        if "crowdstrike" in src_lower:
            return "CrowdStrike EDR"
        elif "splunk" in src_lower:
            return "Splunk SIEM"
        elif "microsoft sentinel" in src_lower or "azure sentinel" in src_lower:
            return "Microsoft Sentinel"
        elif "defender" in src_lower or "microsoft" in src_lower:
            return "Microsoft Defender"
        elif "palo" in src_lower or re.search(r"\bpan(-?os)?\b", src_lower) or "firewall" in src_lower:
            return "Palo Alto Firewall"
        elif "sentinel" in src_lower:
            return "SentinelOne"
        elif "aws" in src_lower or "guardduty" in src_lower or "cloudtrail" in src_lower:
            return "AWS GuardDuty"
        return src

    @classmethod
    def normalize_alert(cls, payload: Dict[str, Any]) -> Dict[str, Any]:
        """
        Main normalization method. Accepts raw/semi-structured dict payload
        and returns a standardized dictionary ready for database persistence.
        """
        # Extract or generate ID
        alert_id = payload.get("id") or f"ALT-{datetime.now().strftime('%Y')}-{uuid.uuid4().hex[:6].upper()}"
        external_id = payload.get("external_alert_id") or payload.get("external_id") or alert_id

        # Extract timestamp
        raw_ts = payload.get("timestamp") or payload.get("event_time") or payload.get("created_at")
        if isinstance(raw_ts, datetime):
            parsed_ts = raw_ts
        elif isinstance(raw_ts, str):
            try:
                parsed_ts = datetime.fromisoformat(raw_ts.strip().replace("Z", "+00:00"))
            except ValueError:
                parsed_ts = datetime.utcnow()
        else:
            parsed_ts = datetime.utcnow()
        # Everything is stored as naive UTC. Convert aware values; do not just drop their offset.
        if parsed_ts.tzinfo is not None:
            parsed_ts = parsed_ts.astimezone(timezone.utc).replace(tzinfo=None)

        # Source normalization
        source = cls.normalize_source(payload.get("source") or payload.get("source_system"))

        # Title / Name
        title = (
            payload.get("alert_title")
            or payload.get("alert_name")
            or payload.get("title")
            or payload.get("rule_name")
            or "Security Alert Event"
        ).strip()

        # Description
        description = (
            payload.get("description")
            or payload.get("details")
            or payload.get("summary")
            or title
        ).strip()

        # Severity
        raw_sev = payload.get("severity") or payload.get("raw_severity")
        severity = cls.normalize_severity(raw_sev)

        # Entity Extraction
        host = (
            payload.get("host")
            or payload.get("host_name")
            or payload.get("computer_name")
            or payload.get("device_name")
        )
        if host: host = str(host).strip()

        username = (
            payload.get("username")
            or payload.get("user")
            or payload.get("account_name")
            or payload.get("actor")
        )
        if username: username = str(username).strip()

        source_ip = (
            payload.get("source_ip")
            or payload.get("ip_address")
            or payload.get("src_ip")
            or payload.get("client_ip")
        )
        if source_ip: source_ip = str(source_ip).strip()

        destination_ip = (
            payload.get("destination_ip")
            or payload.get("dest_ip")
            or payload.get("target_ip")
        )
        if destination_ip: destination_ip = str(destination_ip).strip()

        file_hash = (
            payload.get("file_hash")
            or payload.get("hash")
            or payload.get("sha256")
            or payload.get("md5")
        )
        if file_hash: file_hash = str(file_hash).strip()

        command_line = (
            payload.get("command_line")
            or payload.get("cmd")
            or payload.get("process_cmd")
            or payload.get("command")
        )
        if command_line: command_line = str(command_line).strip()

        status = cls.normalize_status(payload.get("status"))

        return {
            "id": alert_id,
            "external_alert_id": external_id,
            "timestamp": parsed_ts,
            "source": source,
            "alert_title": title,
            "description": description,
            "severity": severity,
            "host": host,
            "username": username,
            "source_ip": source_ip,
            "destination_ip": destination_ip,
            "file_hash": file_hash,
            "command_line": command_line,
            "status": status,
            "normalized_data": {
                "raw_severity_input": raw_sev,
                "raw_source_input": payload.get("source") or payload.get("source_system"),
                "category": payload.get("category", "Uncategorized"),
                "process_name": payload.get("process_name")
            }
        }
