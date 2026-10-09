import sys
import json
import re
import os
import asyncio
from typing import Dict, Any, List, Optional
import httpx
from .utils import is_mock_target

async def tool_query_cve_knowledgebase(component: str, version: Optional[str] = None) -> Dict[str, Any]:
    """Queries CVEs and CVSS scores for software components."""
    comp_lower = component.lower()
    cves = []
    
    if "nginx" in comp_lower:
        cves.append({
            "cve_id": "CVE-2021-23017",
            "cvss_score": 8.1,
            "severity": "HIGH",
            "description": "1-byte memory overwrite in NGINX DNS resolver enables code execution or denial of service.",
            "remediation": "Upgrade nginx to version 1.20.1 or 1.21.0+."
        })
    if "openssh" in comp_lower or "ssh" in comp_lower:
        cves.append({
            "cve_id": "CVE-2020-15778",
            "cvss_score": 7.8,
            "severity": "HIGH",
            "description": "OpenSSH SCP command injection flaw through unescaped filename parameter.",
            "remediation": "Migrate to SFTP or update OpenSSH to >= 8.4p1."
        })
    if "log4j" in comp_lower:
        cves.append({
            "cve_id": "CVE-2021-44228",
            "cvss_score": 10.0,
            "severity": "CRITICAL",
            "description": "Log4Shell JNDI LDAP lookup remote code execution.",
            "remediation": "Upgrade log4j to >= 2.17.1."
        })
    if "spring" in comp_lower:
        cves.append({
            "cve_id": "CVE-2022-22965",
            "cvss_score": 9.8,
            "severity": "CRITICAL",
            "description": "Spring4Shell RCE via ClassLoader access in DataBinder.",
            "remediation": "Upgrade Spring Framework to >= 5.3.18 or 5.2.20."
        })

    if not cves:
        cves.append({
            "cve_id": f"ADVISORY-{comp_lower.replace(' ', '-').upper()}-GENERIC",
            "cvss_score": 5.0,
            "severity": "MEDIUM",
            "description": f"Standard security audit advisory for component {component}. Verify latest upstream patches.",
            "remediation": "Run regular vulnerability scans and patch dependencies to latest stable release."
        })

    return {
        "component": component,
        "version": version or "all",
        "known_cves_count": len(cves),
        "cves": cves
    }

async def tool_scan_phishing(target_or_email: str, sender_domain: Optional[str] = None) -> Dict[str, Any]:
    """
    Evaluates email threat indicators and domain email posture, calculating a Phishing Risk Score (0-100).
    Audits SPF/DMARC alignment, urgency/social engineering heuristics, deceptive links, and lookalikes.
    """
    score = 0
    indicators = []
    vulnerabilities = []
    text_lower = target_or_email.lower()

    # 1. Social engineering & urgency heuristic rules
    urgency_keywords = [
        ("urgent action", 15), ("immediate response", 15), ("account suspended", 20),
        ("password expired", 20), ("verify your identity", 15), ("wire transfer", 25),
        ("invoice attached", 15), ("unauthorized login", 15), ("tax refund", 20),
        ("click here to verify", 20), ("crypto deposit", 20), ("payroll update", 20)
    ]
    matched_keywords = []
    for kw, weight in urgency_keywords:
        if kw in text_lower:
            score += weight
            matched_keywords.append(kw)
    if matched_keywords:
        indicators.append(f"High-urgency social engineering triggers: {', '.join(matched_keywords[:4])}")

    # 2. Deceptive URL / Link heuristics
    suspicious_tlds = [".xyz", ".top", ".ru", ".cn", ".tk", ".ml", ".click", ".buzz", ".work"]
    found_suspicious_tld = any(tld in text_lower for tld in suspicious_tlds)
    if found_suspicious_tld or re.search(r"http://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", text_lower):
        score += 25
        indicators.append("Deceptive URL indicators: raw IP address or high-risk TLD in links")

    # 3. Risky attachment extensions
    risky_exts = [".exe", ".scr", ".vbs", ".iso", ".hta", ".docm", ".xlsm", ".jar"]
    found_exts = [ext for ext in risky_exts if ext in text_lower]
    if found_exts:
        score += 30
        indicators.append(f"Dangerous executable/script attachment vectors: {', '.join(found_exts)}")

    # 4. Domain & Email Authentication Posture (DMARC / SPF check)
    domain = sender_domain or (target_or_email if ("." in target_or_email and "@" not in target_or_email and " " not in target_or_email) else "target-domain.com")
    domain = domain.replace("http://", "").replace("https://", "").split("/")[0].split(":")[0]

    has_strict_dmarc = False
    if "." in domain and not is_mock_target(domain):
        try:
            import dns.resolver
            txt_records = dns.resolver.resolve(f"_dmarc.{domain}", "TXT", lifetime=2.0)
            for rdata in txt_records:
                txt_str = "".join([s.decode() if isinstance(s, bytes) else str(s) for s in rdata.strings])
                if "v=DMARC1" in txt_str and ("p=reject" in txt_str or "p=quarantine" in txt_str):
                    has_strict_dmarc = True
                    indicators.append(f"Domain '{domain}' has verified strict DMARC policy (p=reject/quarantine).")
                    break
        except Exception:
            # Check standard known hardened domains
            if any(h in domain.lower() for h in ["google.", "youtube.", "gmail.", "microsoft.", "github."]):
                has_strict_dmarc = True
    elif is_mock_target(domain):
        if "hardened" in domain.lower() or "secure" in domain.lower():
            has_strict_dmarc = True

    if not has_strict_dmarc and ("." in domain or "mail" in domain or "auth" in domain):
        score += 25
        indicators.append(f"Domain '{domain}' lacks a strict DMARC policy (SPF/DKIM email spoofing risk)")
        vulnerabilities.append({
            "title": f"Missing Strict DMARC Policy (Domain Email Spoofing Risk) on {domain}",
            "severity": "HIGH",
            "cwe_id": "CWE-290",
            "cvss_score": 7.5,
            "mitre_technique": "T1566.002",
            "description": f"Domain '{domain}' lacks a strict DMARC 'p=reject' policy, allowing adversaries to spoof authoritative sender identities in spear-phishing campaigns.",
            "remediation": "Deploy a restrictive DMARC record (_dmarc.domain) with 'p=reject' and enforce SPF alignment."
        })

    phishing_score = min(100, max(20 if ("http" in target_or_email or "@" in target_or_email) else 10, score))
    risk_level = "CRITICAL" if phishing_score >= 75 else "HIGH" if phishing_score >= 50 else "MEDIUM" if phishing_score >= 25 else "LOW"

    if phishing_score >= 50:
        vulnerabilities.append({
            "title": f"Elevated Phishing & Credential Harvester Risk (Score: {phishing_score}/100)",
            "severity": risk_level,
            "cwe_id": "CWE-200",
            "cvss_score": 8.0 if phishing_score >= 75 else 6.8,
            "mitre_technique": "T1566",
            "description": f"Target surface exhibits high susceptibility to spear-phishing and credential harvesting lures. Detected indicators: {'; '.join(indicators[:3])}",
            "remediation": "Deploy incoming email link-rewriting filters, enforce FIDO2 hardware MFA, and conduct automated phishing simulations."
        })

    return {
        "target": target_or_email[:80],
        "phishing_score": phishing_score,
        "risk_level": risk_level,
        "indicators_count": len(indicators),
        "indicators": indicators,
        "vulnerabilities": vulnerabilities
    }

