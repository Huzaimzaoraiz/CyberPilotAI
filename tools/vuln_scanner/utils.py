import sys
import json
import re
import os
import asyncio
from typing import Dict, Any, List, Optional
import httpx
def log(msg: str):
    sys.stderr.write(f"[VulnMCP] {msg}\n")
    sys.stderr.flush()

# --- Security Analysis Rules & Engines ---

def is_mock_target(target: str) -> bool:
    """Helper to distinguish simulated local/test targets from live external targets."""
    t = (target or "").lower()
    return any(k in t for k in [
        "local", "corp", "test", "example", "mock", "internal", "sandbox", "dummy", "127.0.0.1", "localhost"
    ])

def tool_mitre_mapper(finding_or_cwe: str) -> Dict[str, Any]:
    """
    Maps vulnerability titles, CWE codes, or attack actions to the MITRE ATT&CK framework.
    Returns standard Tactic, Technique ID, Name, and mitigation reference.
    """
    query = str(finding_or_cwe).lower()

    if any(k in query for k in ["sqli", "sql", "injection", "cwe-89"]):
        return {
            "tactic": "Initial Access",
            "tactic_id": "TA0001",
            "technique_id": "T1190",
            "technique_name": "Exploit Public-Facing Application",
            "sub_technique": "SQL Injection",
            "description": "Adversary injects malicious SQL input into public endpoints to bypass authentication or extract backend database records.",
            "mitigation": "M1050 (Exploit Protection), Parameterized Queries / ORM Prepared Statements."
        }
    elif any(k in query for k in ["phish", "email", "dmarc", "spf", "t1566"]):
        return {
            "tactic": "Initial Access",
            "tactic_id": "TA0001",
            "technique_id": "T1566",
            "technique_name": "Phishing",
            "sub_technique": "T1566.002 Spearphishing Link",
            "description": "Adversary sends targeted deceptive communications to trick users into revealing credentials or executing untrusted code.",
            "mitigation": "M1049 (Antivirus/Antimalware), M1054 (Software Configuration: Enforce SPF/DKIM/DMARC reject)."
        }
    elif any(k in query for k in ["rce", "command", "exec", "cwe-78"]):
        return {
            "tactic": "Execution",
            "tactic_id": "TA0002",
            "technique_id": "T1059",
            "technique_name": "Command and Scripting Interpreter",
            "sub_technique": "Unix Shell / PowerShell",
            "description": "Adversary abuses command and script interpreters to execute arbitrary commands on the target host.",
            "mitigation": "M1038 (Execution Prevention), Input validation and process sandboxing."
        }
    elif any(k in query for k in ["dir", "dlr", "bruteforce", "enumeration", "t1083", "cwe-538", "cwe-200", ".env"]):
        return {
            "tactic": "Discovery",
            "tactic_id": "TA0007",
            "technique_id": "T1083",
            "technique_name": "File and Directory Discovery",
            "sub_technique": "T1595.003 Wordlist Scanning",
            "description": "Adversary enumerates files and directories to locate sensitive configurations, credentials, and unprotected administrative panels.",
            "mitigation": "M1022 (Restrict File and Directory Permissions), Disable directory indexing."
        }
    elif any(k in query for k in ["api", "bola", "idor", "cwe-639", "swagger"]):
        return {
            "tactic": "Initial Access",
            "tactic_id": "TA0001",
            "technique_id": "T1190",
            "technique_name": "Exploit Public-Facing Application",
            "sub_technique": "API Abuse / Broken Authorization",
            "description": "Adversary exploits flawed object-level authorization or unauthenticated API routes to access unauthorized resources.",
            "mitigation": "M1026 (Privileged Account Management), Centralized API gateway authorization."
        }
    elif any(k in query for k in ["cred", "password", "token", "t1552", "leak"]):
        return {
            "tactic": "Credential Access",
            "tactic_id": "TA0006",
            "technique_id": "T1552",
            "technique_name": "Unsecured Credentials",
            "sub_technique": "Credentials in Files",
            "description": "Adversary searches compromised files, repositories, or network shares for plaintext secrets and API keys.",
            "mitigation": "M1027 (Password Policies), Secrets management vault with automated key rotation."
        }
    elif any(k in query for k in ["pivot", "lateral", "ssrf", "tunnel", "t1021", "t1210"]):
        return {
            "tactic": "Lateral Movement",
            "tactic_id": "TA0008",
            "technique_id": "T1210",
            "technique_name": "Exploitation of Remote Services",
            "sub_technique": "Internal Subnet Pivoting",
            "description": "Adversary leverages compromised DMZ hosts or SSRF channels to exploit services on adjacent internal network segments.",
            "mitigation": "M1030 (Network Segmentation), Zero-trust internal network micro-segmentation."
        }
    elif any(k in query for k in ["database", "jewel", "crown", "vault", "dump", "exfil"]):
        return {
            "tactic": "Collection",
            "tactic_id": "TA0009",
            "technique_id": "T1530",
            "technique_name": "Data from Cloud Storage / Database Object",
            "sub_technique": "Automated Database Exfiltration",
            "description": "Adversary accesses and exfiltrates structured database tables, customer records, and crown jewel assets.",
            "mitigation": "M1041 (Encrypt Sensitive Information), Database activity monitoring (DAM) and egress filtering."
        }
    else:
        return {
            "tactic": "Initial Access",
            "tactic_id": "TA0001",
            "technique_id": "T1190",
            "technique_name": "Exploit Public-Facing Application",
            "sub_technique": "General Application Weakness",
            "description": f"Security finding '{finding_or_cwe}' mapped to general application exploitation surface.",
            "mitigation": "M1050 (Exploit Protection), Regular security patching and hardening."
        }

# --- MCP Protocol Definition & Stdio Loop ---

TOOLS_METADATA = [
    {
        "name": "scan_sqli",
        "description": "Scans code, query strings, or endpoints for SQL Injection vulnerabilities (CWE-89), identifying unescaped parameter concatenations, raw cursor queries, and injection signatures.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "File path, source code string, or endpoint URL to scan for SQL Injection."
                },
                "param_name": {
                    "type": "string",
                    "description": "Optional specific parameter name to test."
                }
            },
            "required": ["target"]
        }
    },
    {
        "name": "scan_xss",
        "description": "Scans code, templates, or URLs for Cross-Site Scripting (XSS) vulnerabilities (CWE-79), identifying unescaped innerHTML sinks, unescaped template tags, and script reflection.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "File path, source code string, or URL to inspect for XSS sinks."
                }
            },
            "required": ["target"]
        }
    },
    {
        "name": "scan_code_sast",
        "description": "Runs a comprehensive Static Application Security Testing (SAST) scan on code or files, detecting SQLi, XSS, Command Injection, Path Traversal, Insecure Deserialization, and Hardcoded Secrets.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "file_path_or_code": {
                    "type": "string",
                    "description": "Path to source file/directory or raw source code snippet to audit."
                },
                "language": {
                    "type": "string",
                    "description": "Optional programming language (python, javascript, php, etc.)."
                }
            },
            "required": ["file_path_or_code"]
        }
    },
    {
        "name": "scan_web_vulnerabilities",
        "description": "Performs web vulnerability auditing on an HTTP endpoint, checking for missing security headers (CSP, HSTS, X-Frame-Options), CORS flaws, and injection vectors (SQLi, XSS).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "url": {
                    "type": "string",
                    "description": "Target web URL or domain (e.g. https://example.com or http://localhost:8000)."
                },
                "check_injection": {
                    "type": "boolean",
                    "description": "Whether to check for SQLi and XSS test points (default: true)."
                }
            },
            "required": ["url"]
        }
    },
    {
        "name": "query_cve_knowledgebase",
        "description": "Queries the CVE threat database for known vulnerabilities, CVSS base scores, and remediation advisories for components (Nginx, OpenSSH, Log4j, Spring, etc.).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "component": {
                    "type": "string",
                    "description": "Software component, library, or service name."
                },
                "version": {
                    "type": "string",
                    "description": "Optional component version."
                }
            },
            "required": ["component"]
        }
    },
    {
        "name": "scan_phishing",
        "description": "Evaluates email content, headers, or domains for phishing risk, calculating a normalized 0-100 Phishing Score and analyzing SPF/DMARC authentication posture.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target_or_email": {
                    "type": "string",
                    "description": "Email body content, raw headers, or target domain name to audit."
                },
                "sender_domain": {
                    "type": "string",
                    "description": "Optional explicit sender domain to check."
                }
            },
            "required": ["target_or_email"]
        }
    },
    {
        "name": "dlr_bruteforce",
        "description": "Performs sensitive directory and file discovery (e.g. /.env, /.git, /admin, /swagger.json, /backup.zip, /metrics) on a web target to uncover perimeter exposures.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target_url": {
                    "type": "string",
                    "description": "Web target URL or domain to audit for exposed directories and sensitive files."
                },
                "wordlist_type": {
                    "type": "string",
                    "description": "Wordlist category ('common', 'critical', 'full'). Default is 'common'."
                }
            },
            "required": ["target_url"]
        }
    },
    {
        "name": "api_endpoint_scanner",
        "description": "Scans web applications for API routes, OpenAPI/Swagger specifications, and OWASP API Top 10 vulnerabilities (BOLA, Broken Authentication, Sensitive Parameter Exposure).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target_url": {
                    "type": "string",
                    "description": "Target web application URL or API host."
                },
                "deep_scan": {
                    "type": "boolean",
                    "description": "Whether to perform deep heuristic route probing."
                }
            },
            "required": ["target_url"]
        }
    },
    {
        "name": "mitre_mapper",
        "description": "Maps any vulnerability, CWE, CVE, or attack technique to the official MITRE ATT&CK framework (Tactic, Technique ID, Name, and Mitigation).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "finding_or_cwe": {
                    "type": "string",
                    "description": "Vulnerability title, CWE identifier (e.g. CWE-89), or attack technique name."
                }
            },
            "required": ["finding_or_cwe"]
        }
    },
    {
        "name": "scan_owasp_top10",
        "description": "Performs an end-to-end security architecture and risk audit against the OWASP Top 10 (2021) categories (A01 through A10).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target_url": {
                    "type": "string",
                    "description": "Web target URL or domain to audit against OWASP Top 10."
                }
            },
            "required": ["target_url"]
        }
    }
]

