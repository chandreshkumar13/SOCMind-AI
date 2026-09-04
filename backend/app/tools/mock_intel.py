from typing import Dict, Any

def query_mock_ip_reputation(ip: str) -> Dict[str, Any]:
    """Mock IP Threat Intelligence lookup tool."""
    return {
        "ip": ip,
        "is_malicious": ip.startswith("185.") or ip.startswith("198."),
        "reputation_score": 88 if ip.startswith("185.") else 15,
        "source": "MockThreatIntel"
    }

def query_mock_hash_reputation(file_hash: str) -> Dict[str, Any]:
    """Mock File Hash Threat Intelligence lookup tool."""
    return {
        "hash": file_hash,
        "detection_ratio": "48/72",
        "threat_name": "Trojan.Generic.Heuristic",
        "source": "MockVirusTotal"
    }
