from typing import Dict, Any

class TriageAgent:
    """
    Triage Agent Placeholder
    Analyzes normalized alerts, assigns severity/priority score,
    and explains why an alert is suspicious.
    """
    def __init__(self, model_name: str = "default"):
        self.agent_name = "Triage Agent"
        self.model_name = model_name

    def analyze_alert(self, alert_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Placeholder method for triaging a security alert.
        Will be implemented in phase 2.
        """
        raw_severity = alert_data.get("raw_severity", "Medium")
        return {
            "agent": self.agent_name,
            "status": "placeholder",
            "alert_id": alert_data.get("id"),
            "assigned_severity": raw_severity,
            "suspicion_score": 75 if raw_severity in ["High", "Critical"] else 40,
            "rationale": "Placeholder triage rationale based on alert metadata."
        }
