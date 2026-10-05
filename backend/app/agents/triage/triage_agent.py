import re
from typing import Dict, Any, List, Optional


class TriageAgent:
    """
    Deterministic Triage Agent.
    Analyzes normalized alert fields, detects security indicators,
    calculates an explainable suspicion score (0-100), assigns priority,
    and generates a human-readable triage rationale.
    """

    def __init__(self, model_version: str = "v1.0-deterministic"):
        self.agent_name = "Triage Agent"
        self.model_version = model_version

    def analyze_alert(self, alert_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Main triage logic. Accepts an AlertModel dict or standard alert dictionary.
        """
        alert_id = str(alert_data.get("id") or alert_data.get("alert_id") or "UNKNOWN")
        raw_sev = str(alert_data.get("severity") or alert_data.get("raw_severity") or "MEDIUM").strip().upper()

        # Base signal score from severity
        severity_base_scores = {
            "CRITICAL": 50,
            "HIGH": 35,
            "MEDIUM": 20,
            "LOW": 10,
            "INFO": 5
        }
        base_score = severity_base_scores.get(raw_sev, 20)

        indicators: List[str] = []
        added_points = 0

        # 1. Entity Presence Indicators
        src_ip = alert_data.get("source_ip") or alert_data.get("ip_address")
        if src_ip and str(src_ip).strip():
            indicators.append(f"Source IP present: {src_ip}")
            added_points += 5

        dest_ip = alert_data.get("destination_ip")
        if dest_ip and str(dest_ip).strip():
            indicators.append(f"Destination IP present: {dest_ip}")
            added_points += 5

        file_hash = alert_data.get("file_hash") or alert_data.get("hash")
        if file_hash and str(file_hash).strip():
            indicators.append(f"File hash artifact present: {str(file_hash)[:16]}...")
            added_points += 5

        # 2. Command Line Pattern Detection (DATA ONLY - NO EXECUTION)
        cmd = str(alert_data.get("command_line") or alert_data.get("cmd") or "").strip().lower()
        if cmd:
            if any(p in cmd for p in ["-e ", "-encodedcommand", "aw52b2tl", "base64"]):
                indicators.append("Encoded or obfuscated command execution pattern detected")
                added_points += 20

            if any(p in cmd for p in ["minidump", "comsvcs", "lsass", "rundll32"]):
                indicators.append("High-risk process memory access pattern detected")
                added_points += 25

            if any(p in cmd for p in ["downloadstring", "invoke-webrequest", "curl ", "wget ", "bitsadmin"]):
                indicators.append("Outbound script payload download pattern detected")
                added_points += 15

            if any(p in cmd for p in ["reg.exe add", "schtasks", "sc create"]):
                indicators.append("Administrative persistence registry/task command pattern detected")
                added_points += 15

            if any(p in cmd for p in ["executionpolicy bypass", "-noprofile", "-windowstyle hidden"]):
                indicators.append("PowerShell execution policy bypass or hidden flags detected")
                added_points += 10

        # 3. Title & Description Security Keywords
        title = str(alert_data.get("alert_title") or alert_data.get("alert_name") or "").lower()
        desc = str(alert_data.get("description") or "").lower()
        combined_text = f"{title} {desc}"

        high_impact_keywords = ["ransomware", "c2", "command & control", "beaconing", "exfiltration", "privilege escalation"]
        for kw in high_impact_keywords:
            if kw in combined_text:
                indicators.append(f"High-impact threat category keyword matched: '{kw}'")
                added_points += 20
                break

        cred_keywords = ["brute force", "failed ssh", "failed login", "kerberoasting", "password spray"]
        for kw in cred_keywords:
            if kw in combined_text:
                indicators.append(f"Credential attack category keyword matched: '{kw}'")
                added_points += 15
                break

        anomaly_keywords = ["unusual", "abnormal", "suspicious", "unrecognized", "tunneling"]
        for kw in anomaly_keywords:
            if kw in combined_text:
                indicators.append(f"Suspicious behavior category keyword matched: '{kw}'")
                added_points += 10
                break

        # 4. Privileged User Context
        username = str(alert_data.get("username") or alert_data.get("user") or "").lower()
        privileged_users = ["root", "admin", "administrator", "s.administrator", "domain admin", "system", "admin_svc", "admin-temp"]
        if username in privileged_users:
            indicators.append(f"Privileged user context detected: '{username}'")
            added_points += 10

        # Calculate final suspicion score (Capped at 100)
        suspicion_score = min(100, base_score + added_points)

        # Assign calculated priority
        if suspicion_score >= 80:
            priority = "CRITICAL"
        elif suspicion_score >= 60:
            priority = "HIGH"
        elif suspicion_score >= 40:
            priority = "MEDIUM"
        elif suspicion_score >= 20:
            priority = "LOW"
        else:
            priority = "INFO"

        # Construct human-readable rationale
        ind_summary = "\n".join([f"  • {ind}" for ind in indicators]) if indicators else "  • No additional risk indicators detected."
        rationale = (
            f"Base severity signal '{raw_sev}' yielded a base score of {base_score} pts. "
            f"Triage engine evaluated alert metadata and identified {len(indicators)} risk indicator(s) (+{added_points} pts):\n"
            f"{ind_summary}\n"
            f"Final calculated suspicion score: {suspicion_score}/100. Assigned Triage Priority: {priority}."
        )

        return {
            "agent": self.agent_name,
            "model_version": self.model_version,
            "status": "completed",
            "alert_id": alert_id,
            "assigned_severity": raw_sev,
            "priority": priority,
            "suspicion_score": suspicion_score,
            "indicators": indicators,
            "rationale": rationale
        }
