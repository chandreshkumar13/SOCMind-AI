import re
import ipaddress
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional, Set, Tuple

from app.tools.mock_intel import (
    query_mock_ip_reputation,
    query_mock_hash_reputation,
    query_mock_domain_reputation,
    query_mock_url_reputation
)

# Common non-domain file extensions to filter out from domain extraction
NON_DOMAIN_EXTENSIONS = {
    "exe", "dll", "bat", "ps1", "json", "txt", "py", "sys", "dmp",
    "doc", "docx", "pdf", "zip", "rar", "locked", "csv", "xml", "log", "tmp", "dat"
}

# Regex patterns
IPV4_REGEX = re.compile(r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b')
IPV6_REGEX = re.compile(
    r'(?i)(?:'
    r'(?:[0-9a-f]{1,4}:){7}[0-9a-f]{1,4}'          # full 8-group
    r'|(?:[0-9a-f]{1,4}:){1,7}:'                    # trailing ::
    r'|:(?::[0-9a-f]{1,4}){1,7}'                    # leading ::
    r'|(?:[0-9a-f]{1,4}:){1,6}:[0-9a-f]{1,4}'
    r'|(?:[0-9a-f]{1,4}:){1,5}(?::[0-9a-f]{1,4}){1,2}'
    r'|(?:[0-9a-f]{1,4}:){1,4}(?::[0-9a-f]{1,4}){1,3}'
    r'|(?:[0-9a-f]{1,3}:){1,3}(?::[0-9a-f]{1,4}){1,4}'
    r'|(?:[0-9a-f]{1,4}:){1,2}(?::[0-9a-f]{1,4}){1,5}'
    r'|[0-9a-f]{1,4}:(?::[0-9a-f]{1,4}){1,6}'
    r'|::(?:ffff(?::0{1,4})?:)?(?:(?:25[0-5]|(?:2[0-4]|1?[0-9])?[0-9])\.){3}'
    r'(?:25[0-5]|(?:2[0-4]|1?[0-9])?[0-9])'        # IPv4-mapped
    r'|::1'                                           # loopback
    r'|::'                                            # unspecified
    r')'
)
MD5_REGEX = re.compile(r'\b[a-fA-F0-9]{32}\b')
SHA1_REGEX = re.compile(r'\b[a-fA-F0-9]{40}\b')
SHA256_REGEX = re.compile(r'\b[a-fA-F0-9]{64}\b')
URL_REGEX = re.compile(r'https?://[^\s<>"\'()]+')
DOMAIN_REGEX = re.compile(r'\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b')


class EnrichmentAgent:
    """
    Deterministic Threat Intelligence Enrichment Agent.
    Extracts Indicators of Compromise (IPs, hashes, domains, URLs) from
    alert data, classifies them, queries local mock threat intelligence,
    and returns structured evidence without making network calls.
    """

    def __init__(self, mock_mode: bool = True):
        self.agent_name = "Enrichment Agent"
        self.mock_mode = mock_mode

    def enrich_iocs(self, iocs: List[Dict[str, str]]) -> Dict[str, Any]:
        """
        Original interface method for backward compatibility.
        """
        results = []
        for ioc in iocs:
            val = ioc.get("value") or ioc.get("ip") or ioc.get("hash") or ""
            if not val:
                continue
            ioc_type = ioc.get("type", "IP").upper()
            res = self._lookup_ioc(val, ioc_type, ioc.get("source", "manual"))
            results.append(res)

        return {
            "agent": self.agent_name,
            "status": "completed",
            "enriched_iocs_count": len(results),
            "threat_intel_summary": f"Enriched {len(results)} IOC(s) via mock threat intelligence.",
            "results": results
        }

    def enrich_alert(self, alert_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Main Phase 3.2 alert enrichment method.
        Extracts all IOCs from alert structured and free-text fields,
        classifies and deduplicates them, queries mock threat intel,
        and builds structured enrichment output.
        """
        alert_id = str(alert_data.get("id") or alert_data.get("alert_id") or "UNKNOWN")
        extracted_iocs = self.extract_iocs(alert_data)

        ioc_results: List[Dict[str, Any]] = []
        malicious_count = 0
        suspicious_count = 0
        clean_count = 0
        unknown_count = 0

        for ioc in extracted_iocs:
            val = ioc["value"]
            ioc_type = ioc["type"]
            field_source = ioc["source"]

            intel_res = self._lookup_ioc(val, ioc_type, field_source)
            rep = intel_res["reputation"]

            if rep == "MALICIOUS":
                malicious_count += 1
            elif rep == "SUSPICIOUS":
                suspicious_count += 1
            elif rep == "CLEAN":
                clean_count += 1
            else:
                unknown_count += 1

            ioc_results.append(intel_res)

        return {
            "agent": self.agent_name,
            "status": "completed",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "alert_id": alert_id,
            "total_iocs_extracted": len(ioc_results),
            "summary": {
                "malicious": malicious_count,
                "suspicious": suspicious_count,
                "clean": clean_count,
                "unknown": unknown_count
            },
            "iocs": ioc_results
        }

    def extract_iocs(self, alert_data: Dict[str, Any]) -> List[Dict[str, str]]:
        """
        Deterministically extracts and classifies IOCs from alert structured & free-text fields.
        Deduplicates by (type, normalized_value).
        """
        seen: Set[Tuple[str, str]] = set()
        extracted: List[Dict[str, str]] = []

        def add_ioc(val: str, ioc_type: str, source_field: str):
            val_norm = val.strip()
            if ioc_type in ("DOMAIN", "MD5", "SHA1", "SHA256"):
                val_norm = val_norm.lower()

            key = (ioc_type, val_norm)
            if key not in seen and val_norm:
                seen.add(key)
                extracted.append({
                    "value": val_norm,
                    "type": ioc_type,
                    "source": source_field
                })

        # 1. Inspect Structured Fields First
        src_ip = alert_data.get("source_ip") or alert_data.get("ip_address")
        if src_ip and self._is_valid_ip(str(src_ip)):
            add_ioc(str(src_ip), "IP", "source_ip")

        dest_ip = alert_data.get("destination_ip")
        if dest_ip and self._is_valid_ip(str(dest_ip)):
            add_ioc(str(dest_ip), "IP", "destination_ip")

        file_hash = alert_data.get("file_hash") or alert_data.get("hash")
        if file_hash:
            h_str = str(file_hash).strip()
            h_type = self._classify_hash_type(h_str)
            if h_type:
                add_ioc(h_str, h_type, "file_hash")

        # 2. Inspect Free-Text Fields
        text_sources = [
            ("command_line", alert_data.get("command_line")),
            ("alert_title", alert_data.get("alert_title") or alert_data.get("alert_name")),
            ("description", alert_data.get("description"))
        ]

        for field_name, content in text_sources:
            if not content or not isinstance(content, str):
                continue

            text = str(content)

            # Extract URLs
            for url_match in URL_REGEX.findall(text):
                add_ioc(url_match, "URL", field_name)

            # Extract IPv4 addresses
            for ip_match in IPV4_REGEX.findall(text):
                if self._is_valid_ip(ip_match):
                    add_ioc(ip_match, "IP", field_name)

            # Extract IPv6 addresses
            for ipv6_match in IPV6_REGEX.findall(text):
                if self._is_valid_ip(ipv6_match):
                    add_ioc(ipv6_match, "IP", field_name)

            # Extract Hashes (SHA256, SHA1, MD5)
            for sha256_match in SHA256_REGEX.findall(text):
                add_ioc(sha256_match, "SHA256", field_name)

            for sha1_match in SHA1_REGEX.findall(text):
                # Avoid matching inside SHA256
                if len(sha1_match) == 40 and not any(sha1_match in h["value"] for h in extracted if h["type"] == "SHA256"):
                    add_ioc(sha1_match, "SHA1", field_name)

            for md5_match in MD5_REGEX.findall(text):
                if len(md5_match) == 32 and not any(md5_match in h["value"] for h in extracted if h["type"] in ("SHA256", "SHA1")):
                    add_ioc(md5_match, "MD5", field_name)

            # Extract Domains
            for dom_match in DOMAIN_REGEX.findall(text):
                dom_clean = dom_match.lower()
                ext = dom_clean.split(".")[-1]
                if ext not in NON_DOMAIN_EXTENSIONS and not self._is_valid_ip(dom_clean):
                    add_ioc(dom_clean, "DOMAIN", field_name)

        return extracted

    def _lookup_ioc(self, val: str, ioc_type: str, source_field: str) -> Dict[str, Any]:
        """
        Routes IOC lookup to appropriate mock intelligence tool.
        """
        if ioc_type == "IP":
            raw_intel = query_mock_ip_reputation(val)
        elif ioc_type in ("MD5", "SHA1", "SHA256"):
            raw_intel = query_mock_hash_reputation(val)
        elif ioc_type == "DOMAIN":
            raw_intel = query_mock_domain_reputation(val)
        elif ioc_type == "URL":
            raw_intel = query_mock_url_reputation(val)
        else:
            raw_intel = {
                "reputation": "UNKNOWN",
                "confidence": 0.0,
                "evidence": f"Unsupported IOC type '{ioc_type}'.",
                "source": "MockThreatIntel"
            }

        return {
            "value": val,
            "type": ioc_type,
            "source": source_field,
            "reputation": raw_intel.get("reputation", "UNKNOWN"),
            "confidence": raw_intel.get("confidence", 0.0),
            "evidence": raw_intel.get("evidence", "No threat intelligence record found."),
            "provider": raw_intel.get("source", "mock_intel")
        }

    @staticmethod
    def _is_valid_ip(ip_str: str) -> bool:
        try:
            ipaddress.ip_address(ip_str.strip())
            return True
        except ValueError:
            return False

    @staticmethod
    def _classify_hash_type(hash_str: str) -> Optional[str]:
        cleaned = hash_str.strip()
        if len(cleaned) == 64 and re.match(r'^[a-fA-F0-9]{64}$', cleaned):
            return "SHA256"
        elif len(cleaned) == 40 and re.match(r'^[a-fA-F0-9]{40}$', cleaned):
            return "SHA1"
        elif len(cleaned) == 32 and re.match(r'^[a-fA-F0-9]{32}$', cleaned):
            return "MD5"
        return None
