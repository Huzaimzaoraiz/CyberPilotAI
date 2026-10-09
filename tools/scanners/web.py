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

async def header_analyzer(url: str) -> Dict[str, Any]:
    """
    Audits HTTP security headers: CSP, HSTS, X-Frame-Options, X-Content-Type-Options, CORS.
    Returns structured analysis and identified vulnerabilities.
    """
    logger.info(f"[HeaderAnalyzer] Checking security headers for {url}...")
    return await tool_scan_web_vulnerabilities(url, check_injection=False)

def _sync_ssl_probe(host: str) -> Dict[str, Any]:
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((host, 443), timeout=2.0) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                return {
                    "has_tls": True,
                    "version": ssock.version(),
                    "cipher": ssock.cipher(),
                    "vulnerabilities": []
                }
    except Exception as e:
        return {
            "has_tls": False,
            "error": str(e),
            "vulnerabilities": [{
                "title": f"Cleartext HTTP Transmission (Missing TLS/HTTPS) on {host}",
                "severity": "HIGH",
                "cwe_id": "CWE-319",
                "owasp_category": "A02:2021-Cryptographic Failures",
                "cvss_score": 7.4,
                "mitre_technique": "T1040",
                "test_payload": f"curl -I http://{host} (Check Cleartext HTTP Transmission)",
                "expected_marker": "CLEARTEXT_HTTP_TRANSMISSION_CONFIRMED",
                "remediation": "Enforce HTTPS encryption via TLS 1.3 certificate and configure HTTP-to-HTTPS 301 redirect."
            }]
        }

async def ssl_checker(domain: str) -> Dict[str, Any]:
    """
    Validates SSL/TLS certificate validity, weak ciphers, and protocol version.
    """
    host = clean_target_host(domain)
    logger.info(f"[SSLChecker] Checking TLS/SSL configuration on {host}...")
    if is_mock_target(domain):
        if "insecure" in domain.lower() or "cleartext" in domain.lower() or domain.startswith("http://"):
            return {
                "domain": host,
                "has_tls": False,
                "vulnerabilities": [{
                    "title": f"Cleartext HTTP Transmission (Missing TLS/HTTPS) on {host}",
                    "severity": "HIGH",
                    "cwe_id": "CWE-319",
                    "owasp_category": "A02:2021-Cryptographic Failures",
                    "cvss_score": 7.4,
                    "mitre_technique": "T1040",
                    "test_payload": f"curl -I http://{host} (Check Cleartext HTTP Transmission)",
                    "expected_marker": "CLEARTEXT_HTTP_TRANSMISSION_CONFIRMED",
                    "remediation": "Enforce HTTPS encryption via TLS 1.3 certificate and configure HTTP-to-HTTPS 301 redirect."
                }]
            }
        return {"domain": host, "has_tls": True, "version": "TLSv1.3", "vulnerabilities": []}

    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, lambda: _sync_ssl_probe(host))

async def web_crawler(target_url: str, max_depth: int = 2, max_pages: int = 8) -> Dict[str, Any]:
    """
    Asynchronously crawls web application to discover endpoints, forms, and query parameters.
    Actively and safely audits discovered parameters with non-destructive canary payloads
    to detect SQL Injection (CWE-89) and Reflected Cross-Site Scripting (CWE-79).
    """
    base_url = target_url.strip()
    if not base_url.startswith("http://") and not base_url.startswith("https://"):
        base_url = f"http://{base_url}"

    clean_host = clean_target_host(base_url)
    discovered_endpoints = []
    discovered_forms = []
    discovered_params = set()
    vulnerabilities = []

    # 1. Deterministic simulation for mock / lab targets
    if is_mock_target(base_url):
        b_low = base_url.lower()
        if any(k in b_low for k in ["portal", "app", "web", "shop", "vuln", "user", "login", "test"]):
            discovered_endpoints = [
                f"{base_url}/search.php?test=query",
                f"{base_url}/artists.php?artist=1",
                f"{base_url}/listproducts.php?cat=1",
                f"{base_url}/login.php"
            ]
            discovered_params = {"artist", "cat", "test", "search"}
            vulnerabilities.append({
                "title": "SQL Injection in parameter 'artist' (CWE-89)",
                "severity": "HIGH",
                "cwe_id": "CWE-89",
                "owasp_category": "A03:2021-Injection",
                "cvss_score": 8.9,
                "mitre_technique": "T1190",
                "endpoint": f"{base_url}/artists.php?artist=1",
                "parameter": "artist",
                "test_payload": "' OR '1'='1' --",
                "expected_marker": "syntax error near",
                "remediation": "Use parameterized queries and prepared statements. Never concatenate user input into SQL strings."
            })
            vulnerabilities.append({
                "title": "Reflected Cross-Site Scripting (XSS) in parameter 'test' (CWE-79)",
                "severity": "HIGH",
                "cwe_id": "CWE-79",
                "owasp_category": "A03:2021-Injection",
                "cvss_score": 7.5,
                "mitre_technique": "T1190",
                "endpoint": f"{base_url}/search.php?test=query",
                "parameter": "test",
                "test_payload": "<script>/*canary*/alert(1)</script>",
                "expected_marker": "<script>/*canary*/alert(1)</script>",
                "remediation": "Implement context-aware HTML entity encoding and enforce Content Security Policy (CSP)."
            })
            return {
                "target_url": base_url,
                "endpoints_discovered": len(discovered_endpoints),
                "endpoints": discovered_endpoints,
                "forms_discovered": 2,
                "parameters_analyzed": list(discovered_params),
                "vulnerabilities": vulnerabilities
            }
        return {
            "target_url": base_url,
            "endpoints_discovered": 1,
            "endpoints": [base_url],
            "forms_discovered": 0,
            "parameters_analyzed": [],
            "vulnerabilities": []
        }

    # 2. Live Crawl & Active Benign Parameter Auditing
    to_visit = [base_url]
    visited = set()
    async with httpx.AsyncClient(verify=False, timeout=2.5, follow_redirects=True) as client:
        while to_visit and len(visited) < max_pages:
            current_url = to_visit.pop(0)
            if current_url in visited:
                continue
            visited.add(current_url)
            discovered_endpoints.append(current_url)

            try:
                resp = await client.get(current_url)
                body = resp.text
            except Exception:
                continue

            # Extract internal links
            for match in re.finditer(r'<a\s+(?:[^>]*?\s+)?href=["\']([^"\']+)["\']', body, re.IGNORECASE):
                href = match.group(1).strip()
                if href.startswith("javascript:") or href.startswith("mailto:") or href.startswith("#"):
                    continue
                full = href if href.startswith("http") else urljoin(base_url, href)
                parsed = urlparse(full)
                if parsed.hostname == clean_host and full not in visited and full not in to_visit:
                    to_visit.append(full)

            # Extract forms & inputs
            for form_match in re.finditer(r'<form\s+([^>]*?)>(.*?)</form>', body, re.IGNORECASE | re.DOTALL):
                form_attrs, form_content = form_match.group(1), form_match.group(2)
                action_match = re.search(r'action=["\']([^"\']*)["\']', form_attrs, re.IGNORECASE)
                action = action_match.group(1).strip() if action_match else current_url
                full_action = action if action.startswith("http") else urljoin(base_url, action)
                inputs = re.findall(r'<input\s+[^>]*?name=["\']([^"\']+)["\']', form_content, re.IGNORECASE)
                discovered_forms.append({"action": full_action, "inputs": inputs})
                for inp in inputs:
                    discovered_params.add(inp)

            # Extract query parameters from URL
            query = urlparse(current_url).query
            if query:
                for qpart in query.split("&"):
                    if "=" in qpart:
                        k, _ = qpart.split("=", 1)
                        discovered_params.add(k)

        # Active Benign Probing for SQLi & XSS on discovered endpoints with parameters
        tested_params = set()
        for p_url in list(discovered_endpoints):
            parsed_p = urlparse(p_url)
            if not parsed_p.query:
                continue
            qs = parse_qs(parsed_p.query)
            for param, vals in qs.items():
                if param in tested_params:
                    continue
                tested_params.add(param)

                # Test 1: SQL Injection Error-Based Probe
                sqli_probe = "'"
                sqli_query = dict(qs)
                sqli_query[param] = [vals[0] + sqli_probe if vals else sqli_probe]
                test_sqli_url = urlunparse(parsed_p._replace(query=urlencode(sqli_query, doseq=True)))

                try:
                    sqli_resp = await client.get(test_sqli_url)
                    s_body = sqli_resp.text.lower()
                    sql_errors = [
                        "you have an error in your sql syntax",
                        "syntax error near",
                        "unclosed quotation mark",
                        "mysql_fetch",
                        "mysql_query",
                        "pg_query",
                        "sqlite3.operationalerror",
                        "ora-01756",
                        "ora-00933",
                        "postgresql query failed"
                    ]
                    for err in sql_errors:
                        if err in s_body:
                            vulnerabilities.append({
                                "title": f"SQL Injection in parameter '{param}' (CWE-89)",
                                "severity": "HIGH",
                                "cwe_id": "CWE-89",
                                "owasp_category": "A03:2021-Injection",
                                "cvss_score": 8.9,
                                "mitre_technique": "T1190",
                                "endpoint": p_url,
                                "parameter": param,
                                "test_payload": "' OR '1'='1' --",
                                "expected_marker": err,
                                "remediation": "Use parameterized SQL statements (prepared statements) to prevent untrusted input interpretation."
                            })
                            break
                except Exception:
                    pass

                # Test 2: Reflected XSS Canary Probe
                xss_canary = "<script>/*canary*/alert(1)</script>"
                xss_query = dict(qs)
                xss_query[param] = [xss_canary]
                test_xss_url = urlunparse(parsed_p._replace(query=urlencode(xss_query, doseq=True)))

                try:
                    xss_resp = await client.get(test_xss_url)
                    if xss_canary in xss_resp.text:
                        vulnerabilities.append({
                            "title": f"Reflected Cross-Site Scripting (XSS) in parameter '{param}' (CWE-79)",
                            "severity": "HIGH",
                            "cwe_id": "CWE-79",
                            "owasp_category": "A03:2021-Injection",
                            "cvss_score": 7.5,
                            "mitre_technique": "T1190",
                            "endpoint": p_url,
                            "parameter": param,
                            "test_payload": xss_canary,
                            "expected_marker": xss_canary,
                            "remediation": "Apply context-aware output encoding (HTML, JavaScript, Attribute) and configure Content Security Policy."
                        })
                except Exception:
                    pass

    return {
        "target_url": base_url,
        "endpoints_discovered": len(discovered_endpoints),
        "endpoints": discovered_endpoints,
        "forms_discovered": len(discovered_forms),
        "parameters_analyzed": list(discovered_params),
        "vulnerabilities": vulnerabilities
    }

