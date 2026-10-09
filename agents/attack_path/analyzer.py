import asyncio
import logging
from typing import Dict, Any, List, Optional, Tuple
import networkx as nx
from core.models import VulnerabilityRecord, TargetAsset, TaskItem
def derive_exploitation_path(vuln: VulnerabilityRecord, asset: Optional[TargetAsset] = None) -> Dict[str, Any]:
    """
    Constructs a concrete technical exploitation path showing:
    1. Vector / Endpoint
    2. Exploit payload / technique
    3. Granted capability
    """
    title_lower = vuln.title.lower()
    poc = vuln.proof_of_concept
    asset_name = asset.asset_identifier if asset else "target host"
    
    if any(k in title_lower for k in ["sql", "cwe-89"]):
        sql_poc = poc or "' OR '1'='1"
        return {
            "method": "POST /api/v1/auth/login or GET /api/search?id=",
            "payload": poc or "' OR '1'='1' UNION SELECT username, password_hash FROM users--",
            "technique": "CWE-89: SQL Injection Parameter Interpolation",
            "mitre": "T1190 - Exploit Public-Facing Application",
            "capability": "Database Query Execution & Credential Extraction",
            "summary": f"Attacker injects SQL payload '{sql_poc}' on {asset_name}, extracting database authentication hashes."
        }
    elif any(k in title_lower for k in ["rce", "command injection", "cwe-78"]):
        rce_poc = poc or "; whoami"
        return {
            "method": "POST /admin/exec or /diagnostic",
            "payload": poc or "; id; whoami; uname -a",
            "technique": "CWE-78: OS Command Injection via Shell Metacharacters",
            "mitre": "T1059 - Command and Scripting Interpreter",
            "capability": "Interactive Remote Shell Execution (RCE)",
            "summary": f"Attacker executes command injection payload '{rce_poc}', securing interactive shell control on {asset_name}."
        }
    elif any(k in title_lower for k in ["lfi", "traversal", "cwe-22", "file disclosure"]):
        return {
            "method": "GET /download?file=../../../../etc/passwd",
            "payload": poc or "../../../../etc/passwd or /.env",
            "technique": "CWE-22: Path Traversal / Arbitrary File Read",
            "mitre": "T1083 - File and Directory Discovery",
            "capability": "Local Sensitive Configuration & Key Disclosure",
            "summary": f"Attacker traverses file paths to extract sensitive system files and tokens from {asset_name}."
        }
    elif any(k in title_lower for k in ["cve-2021-23017", "nginx"]):
        return {
            "method": "DNS UDP/TCP Port 53 Response Packet",
            "payload": "Crafted 1-byte DNS PTR overwrite buffer",
            "technique": "CVE-2021-23017: NGINX DNS Resolver 1-Byte Memory Overwrite",
            "mitre": "T1190 - Exploit Public-Facing Application",
            "capability": "Remote Worker Memory Corruption & Hijack",
            "summary": "Attacker delivers malicious DNS payload triggering 1-byte overwrite in Nginx worker, seizing daemon control."
        }
    elif any(k in title_lower for k in ["cve-2020-15778", "openssh", "scp"]):
        return {
            "method": "SSH Port 22 scp Command Invocation",
            "payload": "scp -S '`id`' malicious_file host:",
            "technique": "CVE-2020-15778: OpenSSH scp Command Injection",
            "mitre": "T1059 - Command and Scripting Interpreter",
            "capability": "Remote Command Execution via scp Filename Evaluation",
            "summary": "Attacker abuses backtick command substitution in scp path arguments to achieve remote execution."
        }
    elif any(k in title_lower for k in ["cve-2022-22965", "spring4shell"]):
        return {
            "method": "POST /greeting?class.module.classLoader.resources.context...",
            "payload": "class.module.classLoader.resources.context.parent.pipeline.first.pattern=...",
            "technique": "CVE-2022-22965: Spring4Shell Remote Code Execution",
            "mitre": "T1190 - Exploit Public-Facing Application",
            "capability": "Persistent Webshell Drop & RCE",
            "summary": "Attacker exploits Spring DataBinder to drop a persistent web shell into document root, securing RCE."
        }
    elif any(k in title_lower for k in ["env", "git", "dir", "dlr", "bruteforce", "cwe-538", "cwe-200"]):
        return {
            "method": "HTTP GET /.env or /.git/HEAD",
            "payload": "Direct HTTP GET probe against unindexed path",
            "technique": "CWE-538: File and Directory Information Exposure",
            "mitre": "T1552 - Unsecured Credentials in Files",
            "capability": "Cleartext Database Credentials & Secret Keys",
            "summary": f"Attacker discovers publicly exposed configuration file on {asset_name}, recovering database connection credentials."
        }
    elif any(k in title_lower for k in ["api", "bola", "idor", "cwe-639", "cwe-306"]):
        return {
            "method": "GET /api/v1/users/{id} without authorization header",
            "payload": "IDOR parameter manipulation targeting administrative user IDs",
            "technique": "CWE-639: Broken Object Level Authorization (BOLA)",
            "mitre": "T1078 - Valid Accounts / Privilege Escalation",
            "capability": "Direct Tenant Data Extraction & Account Takeover",
            "summary": f"Attacker queries unprotected API routes on {asset_name}, extracting tenant data and administrative tokens."
        }
    elif any(k in title_lower for k in ["phish", "dmarc", "spf", "email", "t1566"]):
        return {
            "method": "Inbound SMTP Spearphishing Campaign",
            "payload": "Spoofed domain spearphishing lure with credential harvesting portal",
            "technique": "T1566: Phishing / Email Domain Spoofing",
            "mitre": "T1566 - Phishing",
            "capability": "Stolen Employee Credentials & Initial Perimeter Access",
            "summary": f"Attacker exploits missing SPF/DMARC to deliver spoofed corporate lures, harvesting employee access credentials."
        }
    else:
        return {
            "method": f"Targeted Protocol Audit Probe on {asset_name}",
            "payload": poc or "Crafted boundary validation exploit payload",
            "technique": "Application Logic & Security Boundary Flaw",
            "mitre": "T1190 - Exploit Public-Facing Application",
            "capability": "Unauthorized Perimeter Access & Lateral Pivot",
            "summary": f"Attacker exploits {vuln.title} to bypass security boundaries and establish a persistent lateral pivot."
        }


def break_chain_analyzer(graph: nx.DiGraph) -> Dict[str, Any]:
    """Finds which single node removal severs the maximum number of attack paths (chokepoint analysis)."""
    vuln_nodes = [n for n in graph.nodes if n.startswith("VULN:")]
    if not vuln_nodes:
        return {"chokepoint_node": None, "paths_severed": 0, "strategic_recommendation": "No active attack paths."}
    
    initial_paths = len(path_ranker(graph))
    best_node = None
    max_severed = -1
    
    for v in vuln_nodes:
        H = graph.copy()
        H.remove_node(v)
        remaining = len(path_ranker(H))
        severed = initial_paths - remaining
        if severed > max_severed:
            max_severed = severed
            best_node = v
            
    return {
        "chokepoint_node": best_node,
        "paths_severed": max_severed,
        "strategic_recommendation": f"Remediate {best_node} to sever {max_severed} path(s)."
    }


