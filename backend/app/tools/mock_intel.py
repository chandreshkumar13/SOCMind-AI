import ipaddress
from typing import Dict, Any, Optional

# Pre-defined mock malicious databases
KNOWN_MALICIOUS_IPS = {
    "185.220.101.5": "Known command-and-control (C2) server host associated with Cobalt Strike beaconing.",
    "198.51.100.77": "Source of automated SSH brute force attack campaigns.",
    "203.0.113.88": "Known DNS tunneling exfiltration destination endpoint."
}

KNOWN_MALICIOUS_HASHES = {
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855": "Trojan.Generic.PowerShellDownloader (48/72 vendors)",
    "2b8a741369359e19864293fe2f7cfef5f58c70425712ef9e3dfa4b13a8efee5d": "Trojan.Win32.CobaltStrike.DLL (62/72 vendors)",
    "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08": "Ransomware.Win32.GenericEncryptor (59/72 vendors)",
    "c138f387a3243171350a4170e3ed510bbf49a0ec947dfeb6e5ebf8695d7eb80a": "HackTool.Win32.Mimikatz.LSASSDump (65/72 vendors)",
    "4a715f5d6f4618e47d1a293ebc52a0a2df3303d7b32230154673890f55562145": "Trojan.Win32.RegistryAutorunPersistence (42/72 vendors)"
}

KNOWN_MALICIOUS_DOMAINS = {
    "malicious-domain.net": "Known malware distribution domain.",
    "bad-c2-server.com": "Known C2 infrastructure domain.",
    "phishing-login.org": "Credential phishing domain."
}


def query_mock_ip_reputation(ip: str) -> Dict[str, Any]:
    """
    Mock IP Threat Intelligence lookup tool.
    Preserves original keys ('ip', 'is_malicious', 'reputation_score', 'source')
    and adds standardized reputation ('MALICIOUS', 'SUSPICIOUS', 'CLEAN', 'UNKNOWN'),
    confidence, and evidence rationale.
    """
    ip_clean = str(ip).strip()
    is_mal = ip_clean in KNOWN_MALICIOUS_IPS

    if is_mal:
        reputation = "MALICIOUS"
        score = 88
        confidence = 0.95
        evidence = KNOWN_MALICIOUS_IPS.get(ip_clean, "Associated with malicious network scanning or C2 infrastructure.")
    else:
        # Check if private IP
        try:
            ip_obj = ipaddress.ip_address(ip_clean)
            if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local:
                reputation = "CLEAN"
                score = 5
                confidence = 1.0
                evidence = "Internal RFC1918 private network address."
            else:
                reputation = "UNKNOWN"
                score = 15
                confidence = 0.0
                evidence = "No threat intelligence records found for IP."
        except ValueError:
            reputation = "UNKNOWN"
            score = 0
            confidence = 0.0
            evidence = "Invalid IP address syntax."

    return {
        "ip": ip_clean,
        "is_malicious": is_mal,
        "reputation_score": score,
        "reputation": reputation,
        "confidence": confidence,
        "evidence": evidence,
        "source": "MockThreatIntel"
    }


def query_mock_hash_reputation(file_hash: str) -> Dict[str, Any]:
    """
    Mock File Hash Threat Intelligence lookup tool.
    Preserves original keys ('hash', 'detection_ratio', 'threat_name', 'source')
    and adds standardized reputation ('MALICIOUS', 'CLEAN', 'UNKNOWN'),
    confidence, and evidence.
    """
    h_clean = str(file_hash).strip().lower()
    
    if h_clean in KNOWN_MALICIOUS_HASHES:
        threat = KNOWN_MALICIOUS_HASHES.get(h_clean, "Trojan.Generic.Heuristic")
        reputation = "MALICIOUS"
        confidence = 0.98
        evidence = f"Known malicious file hash identified as {threat}."
        detection = "48/72"
    else:
        threat = "None"
        reputation = "UNKNOWN"
        confidence = 0.0
        evidence = "File hash not found in threat intelligence database."
        detection = "0/72"

    return {
        "hash": h_clean,
        "detection_ratio": detection,
        "threat_name": threat,
        "reputation": reputation,
        "confidence": confidence,
        "evidence": evidence,
        "source": "MockVirusTotal"
    }


def query_mock_domain_reputation(domain: str) -> Dict[str, Any]:
    """
    Mock Domain Threat Intelligence lookup tool.
    """
    d_clean = str(domain).strip().lower()
    is_mal = d_clean in KNOWN_MALICIOUS_DOMAINS or any(kw in d_clean for kw in ["malicious", "bad-c2", "phishing-login"])

    if is_mal:
        reputation = "MALICIOUS"
        confidence = 0.90
        evidence = KNOWN_MALICIOUS_DOMAINS.get(d_clean, "Domain flagged for malware hosting or command-and-control activity.")
    else:
        reputation = "UNKNOWN"
        confidence = 0.0
        evidence = "Domain reputation unknown or not listed in threat intelligence database."

    return {
        "domain": d_clean,
        "reputation": reputation,
        "confidence": confidence,
        "evidence": evidence,
        "source": "MockDomainIntel"
    }


def query_mock_url_reputation(url: str) -> Dict[str, Any]:
    """
    Mock URL Threat Intelligence lookup tool.
    """
    u_clean = str(url).strip()
    u_lower = u_clean.lower()

    is_mal = any(d in u_lower for d in KNOWN_MALICIOUS_DOMAINS) or "payload.exe" in u_lower or "malicious" in u_lower

    if is_mal:
        reputation = "MALICIOUS"
        confidence = 0.92
        evidence = "URL points to known malicious executable download or C2 host."
    else:
        reputation = "UNKNOWN"
        confidence = 0.0
        evidence = "URL not found in threat intelligence database."

    return {
        "url": u_clean,
        "reputation": reputation,
        "confidence": confidence,
        "evidence": evidence,
        "source": "MockURLIntel"
    }
