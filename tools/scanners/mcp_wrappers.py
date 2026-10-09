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

async def scan_web_vulnerabilities(target: str) -> List[Dict]:
    """
    Scans a web target for common web application vulnerabilities (SQLi, XSS, CSP/Header flaws).
    """
    logger.info(f"[WebScanner] Auditing web application surface on {target}...")
    result = await tool_scan_web_vulnerabilities(target, check_injection=True)
    return result.get("vulnerabilities", [])

async def scan_owasp_top10(target: str) -> Dict:
    """
    Performs an end-to-end security architecture and risk audit against the OWASP Top 10 (2021) categories (A01 through A10).
    """
    logger.info(f"[OWASPTop10] Auditing target {target} against OWASP Top 10 (2021)...")
    return await tool_scan_owasp_top10(target)

async def scan_code_sast(path_or_code: str) -> List[Dict]:
    """
    Runs SAST scanning for code vulnerabilities (SQLi, XSS, Command Injection, Deserialization).
    """
    logger.info(f"[SAST] Running source code security audit...")
    result = await tool_scan_code_sast(path_or_code)
    return result.get("findings", [])

async def scan_phishing(target_or_email: str, sender_domain: str = None) -> Dict:
    """
    Analyzes email/domain phishing indicators, calculating Phishing Risk Score (0-100) and SPF/DMARC posture.
    """
    logger.info(f"[PhishingDetector] Analyzing phishing threat posture on {target_or_email}...")
    return await tool_scan_phishing(target_or_email, sender_domain)

async def run_dlr_bruteforce(target_url: str, wordlist_type: str = "common") -> Dict:
    """
    Discovers exposed directories (.env, .git, /admin, /swagger.json, /backup.zip) via directory bruteforce.
    """
    logger.info(f"[DirBruteforce] Probing sensitive paths & exposed configs on {target_url}...")
    return await tool_dlr_bruteforce(target_url, wordlist_type)

dir_bruteforce = run_dlr_bruteforce

async def scan_api_endpoints(target_url: str, deep_scan: bool = True) -> Dict:
    """
    Scans web applications for API routes, OpenAPI/Swagger specifications, and OWASP API Top 10 vulnerabilities.
    """
    logger.info(f"[APIScanner] Auditing API surfaces & authentication on {target_url}...")
    return await tool_api_endpoint_scanner(target_url, deep_scan)

api_endpoint_scanner = scan_api_endpoints

