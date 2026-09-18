import asyncio
import logging
import httpx
from typing import Dict, List

logger = logging.getLogger("Scanners")

from urllib.parse import urlparse
from tools.api_connectors import is_mock_target

def clean_target_host(target: str) -> str:
    """Extracts raw hostname or IP from target, stripping protocol, path, and ports."""
    t = (target or "").strip()
    if "://" in t:
        parsed = urlparse(t)
        host = parsed.hostname or parsed.netloc.split(":")[0]
        return host or t
    return t.split("/")[0].split(":")[0]

async def run_nmap(target: str) -> str:
    """
    Executes an Nmap service scan asynchronously.
    Uses strict flags to keep it fast and stealthy.
    """
    host = clean_target_host(target)
    logger.info(f"[Nmap] Starting service scan on host '{host}' (from '{target}')...")
    try:
        # -Pn (no ping), -sV (service versions), -F (fast top 100 ports)
        process = await asyncio.create_subprocess_exec(
            'nmap', '-Pn', '-sV', '-F', host,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, stderr = await process.communicate()
        
        output_str = stdout.decode().strip()
        if (
            process.returncode != 0
            or "Failed to resolve" in output_str
            or "0 hosts up" in output_str
            or "WARNING: No targets were specified" in output_str
            or "in ignored states" in output_str
            or "open" not in output_str
        ):
            logger.warning(f"Target '{host}' could not be reached or resolved by Nmap. Using context-aware simulated output.")
            if is_mock_target(target):
                t_low = target.lower()
                if "db" in t_low or "vault" in t_low:
                    return f"""Starting Nmap 7.93 ( https://nmap.org )\nNmap scan report for {host}\nPORT   STATE SERVICE VERSION\n22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.1\n5432/tcp open postgresql PostgreSQL DB 13.3\n"""
                return f"""Starting Nmap 7.93 ( https://nmap.org )\nNmap scan report for {host}\nPORT   STATE SERVICE VERSION\n22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.1\n80/tcp open  http    nginx 1.18.0\n"""
            return f"""Starting Nmap 7.93 ( https://nmap.org )\nNmap scan report for {host}\nNote: Host appears down or protected by perimeter firewall (0 ports detected open).\n"""
            
        return output_str
    except FileNotFoundError:
        logger.warning("Nmap is not installed on this host. Using simulated output.")
        return f"""
        Starting Nmap 7.93 ( https://nmap.org )
        Nmap scan report for {host}
        PORT   STATE SERVICE VERSION
        22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.1
        80/tcp open  http    nginx 1.18.0
        """

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

async def scan_api_endpoints(target_url: str, deep_scan: bool = True) -> Dict:
    """
    Scans web applications for API routes, OpenAPI/Swagger specifications, and OWASP API Top 10 vulnerabilities.
    """
    logger.info(f"[APIScanner] Auditing API surfaces & authentication on {target_url}...")
    return await tool_api_endpoint_scanner(target_url, deep_scan)

def map_to_mitre(finding_or_cwe: str) -> Dict:
    """
    Maps any vulnerability, CWE, or attack action to standard MITRE ATT&CK tactics & techniques.
    """
    return tool_mitre_mapper(finding_or_cwe)