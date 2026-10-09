import asyncio
import logging
import httpx
import re
import socket
import ssl
from typing import Dict, List, Any, Optional
from urllib.parse import urlparse, urljoin, parse_qs, urlencode, urlunparse
from tools.api_connectors import is_mock_target

logger = logging.getLogger("Scanners")

async def query_nvd(cpe_string: str, api_key: str = None) -> List[Dict]:
    """
    Queries the National Vulnerability Database for known CVEs affecting a specific CPE.
    If no API key is provided, falls back to simulated data for testing.
    """
    if not api_key:
        logger.info(f"[NVD] No API key provided. Simulating query for {cpe_string}")
        cpe_lower = cpe_string.lower()
        if "nginx" in cpe_lower:
            return [{
                "cve_id": "CVE-2021-23017",
                "description": "A 1-Byte memory overwrite bug in NGINX DNS resolver.",
                "cvss_score": 8.1
            }]
        if "openssh" in cpe_lower or "ssh" in cpe_lower:
            return [{
                "cve_id": "CVE-2020-15778",
                "description": "OpenSSH scp command injection allows command execution.",
                "cvss_score": 7.8
            }]
        if "apache" in cpe_lower:
            return [{
                "cve_id": "CVE-2021-41773",
                "description": "Apache HTTP Server path traversal and file disclosure flaw.",
                "cvss_score": 7.5
            }]
        if "log4j" in cpe_lower:
            return [{
                "cve_id": "CVE-2021-44228",
                "description": "Apache Log4j2 JNDI features RCE vulnerability.",
                "cvss_score": 10.0
            }]
        return []

    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cpeName={cpe_string}"
    headers = {"apiKey": api_key} if api_key else {}
    
    async with httpx.AsyncClient() as client:
        try:
            response = await client.get(url, headers=headers, timeout=10.0)
            response.raise_for_status()
            data = response.json()
            
            results = []
            for item in data.get('vulnerabilities', [])[:3]: # Limit to top 3
                cve = item['cve']
                cvss = cve.get('metrics', {}).get('cvssMetricV31', [{}])[0].get('cvssData', {}).get('baseScore', 5.0)
                results.append({
                    "cve_id": cve['id'],
                    "description": cve['descriptions'][0]['value'],
                    "cvss_score": float(cvss)
                })
            return results
        except Exception as e:
            logger.error(f"[NVD API Error] {str(e)}")
            return []

from tools.vuln_scanner_mcp import (
    tool_scan_sqli,
    tool_scan_xss,
    tool_scan_code_sast,
    tool_scan_web_vulnerabilities,
    tool_query_cve_knowledgebase,
    tool_scan_phishing,
    tool_dlr_bruteforce,
    tool_api_endpoint_scanner,
    tool_mitre_mapper,
    tool_scan_owasp_top10
)

