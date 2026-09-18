import logging
from typing import Dict, Any, List
from core.models import RemediationPlan, VulnerabilityRecord

logger = logging.getLogger("RemediationAgent")

class MockRemediationLLM:
    """Simulates an LLM generating root cause analysis and code patches."""
    
    async def generate_patch(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """
        In production, this passes a strict system prompt to OpenAI/Anthropic 
        forcing a JSON response with the exact schema needed.
        """
        title = context.get("title", "").lower()
        layer = context.get("layer", "")
        
        # 1. OSINT / Threat Intel Fixes (Administrative)
        if layer == "OSINT" or context.get("has_leaked_creds"):
            return {
                "root_cause_analysis": "Employee credentials were leaked in a third-party breach, exposing the perimeter.",
                "target_tech_stack": "IAM / Identity Provider",
                "original_code_snippet": "N/A - Configuration Issue",
                "patched_code_snippet": "1. Invalidate all current active sessions.\n2. Force a global password reset.\n3. Enforce MFA (Multi-Factor Authentication) on all external portals.",
                "patch_type": "configuration"
            }
            
        # 2. Network / Web App Fixes (Code & Config)
        if "nginx" in title or "cve-2021-23017" in title:
            return {
                "root_cause_analysis": "1-Byte memory overwrite bug in NGINX DNS resolver allows arbitrary code execution or denial of service.",
                "target_tech_stack": "Nginx / Linux",
                "original_code_snippet": "nginx version: 1.18.0",
                "patched_code_snippet": "sudo apt-get update\nsudo apt-get install --only-upgrade nginx\n# Upgrade to nginx version 1.20.1 or later",
                "patch_type": "infrastructure"
            }
            
        if "rce" in title or "command injection" in title:
            return {
                "root_cause_analysis": "User input is being passed directly into a system shell execution without sanitization.",
                "target_tech_stack": "Python / Backend",
                "original_code_snippet": "os.system(f'ping -c 4 {user_input}')",
                "patched_code_snippet": "import subprocess\nsubprocess.run(['ping', '-c', '4', user_input], check=True)",
                "patch_type": "code"
            }

        if "sql" in title or "cwe-89" in title:
            return {
                "root_cause_analysis": "Untrusted input interpolated directly into SQL statement string, exposing the database to SQL injection (CWE-89).",
                "target_tech_stack": "SQL / Python Database Driver",
                "original_code_snippet": "cursor.execute(f'SELECT * FROM users WHERE id = {user_id}')",
                "patched_code_snippet": "cursor.execute('SELECT * FROM users WHERE id = %s', (user_id,))",
                "patch_type": "code"
            }

        if "xss" in title or "cwe-79" in title:
            return {
                "root_cause_analysis": "User-supplied input rendered in HTML DOM without contextual entity escaping or Content Security Policy (CWE-79).",
                "target_tech_stack": "Frontend / JavaScript",
                "original_code_snippet": "document.getElementById('content').innerHTML = userInput;",
                "patched_code_snippet": "document.getElementById('content').textContent = userInput;\n// Or configure CSP: Content-Security-Policy: default-src 'self'",
                "patch_type": "code"
            }

        if "csp" in title or "header" in title or "cwe-693" in title:
            return {
                "root_cause_analysis": "Missing foundational HTTP security headers exposing application to clickjacking and cross-site scripting.",
                "target_tech_stack": "Nginx / Web Server",
                "original_code_snippet": "# Missing security headers in web server configuration",
                "patched_code_snippet": "add_header Content-Security-Policy \"default-src 'self'\";\nadd_header X-Frame-Options \"DENY\";\nadd_header X-Content-Type-Options \"nosniff\";",
                "patch_type": "configuration"
            }

        # 3. Default Fallback
        return {
            "root_cause_analysis": "Improper input validation or insecure configuration.",
            "target_tech_stack": "Unknown",
            "original_code_snippet": "N/A",
            "patched_code_snippet": "# Please review the affected component and apply vendor security patches.",
            "patch_type": "general"
        }

MockLLMClient = MockRemediationLLM

def root_cause_analyzer(finding: Dict[str, Any]) -> str:
    """Explains why the vulnerability exists based on finding context."""
    title = str(finding.get("title", "")).lower()
    if "sql" in title or "cwe-89" in title:
        return "Untrusted user input concatenated directly into raw database query string without parameter binding (CWE-89)."
    elif "xss" in title or "cwe-79" in title:
        return "User input reflected into DOM context without contextual HTML entity encoding or CSP protection (CWE-79)."
    elif "csp" in title or "hsts" in title or "header" in title:
        return "Missing foundational HTTP response security headers in web server configuration (CWE-693)."
    elif "nginx" in title or "23017" in title:
        return "Outdated component with known 1-byte DNS memory corruption vulnerability."
    return finding.get("remediation", "Improper input validation or insecure system default configuration.")

def fix_generator(finding: Dict[str, Any], cve_id: str = None) -> Dict[str, Any]:
    """Generates remediation code or configuration fix suggestions."""
    title = str(finding.get("title", "")).lower()
    if "sql" in title or "cwe-89" in title:
        return {
            "patch_type": "code",
            "fix": "cursor.execute('SELECT * FROM users WHERE id = %s', (user_id,))",
            "guidance": "Bind all variables using parameterized queries or prepared statements."
        }
    elif "xss" in title or "cwe-79" in title:
        return {
            "patch_type": "code",
            "fix": "element.textContent = sanitize(userInput);",
            "guidance": "Enforce context-aware HTML entity escaping and Content-Security-Policy."
        }
    elif "csp" in title or "header" in title:
        return {
            "patch_type": "configuration",
            "fix": "add_header Content-Security-Policy \"default-src 'self'\";\nadd_header Strict-Transport-Security \"max-age=31536000\";",
            "guidance": "Add standard HTTP security headers in web server config."
        }
    return {
        "patch_type": "configuration",
        "fix": finding.get("remediation", "# Review component configuration and apply vendor patches."),
        "guidance": "Consult vendor advisory and upgrade component."
    }

def patch_prioritizer(attack_paths: List[Any], vulnerabilities: List[Any] = None) -> List[Dict[str, Any]]:
    """Orders remediation fixes by attack path impact and chokepoint priority."""
    prioritized = []
    # Identify chokepoints from attack paths first
    chokepoint_ids = set()
    for p in (attack_paths or []):
        p_dict = p if isinstance(p, dict) else getattr(p, "dict", lambda: {})()
        choke = p_dict.get("chokepoint_node")
        if choke:
            chokepoint_ids.add(choke.replace("VULN:", ""))

    for v in (vulnerabilities or []):
        v_dict = v if isinstance(v, dict) else (v.dict() if hasattr(v, "dict") else vars(v))
        vid = v_dict.get("id")
        is_choke = vid in chokepoint_ids
        score = float(v_dict.get("criticality_score", 5.0)) + (3.0 if is_choke else 0.0)
        prioritized.append({
            "vuln_id": vid,
            "title": v_dict.get("title"),
            "priority_score": round(score, 1),
            "is_strategic_chokepoint": is_choke,
            "fix": fix_generator(v_dict)
        })

    prioritized.sort(key=lambda x: x["priority_score"], reverse=True)
    return prioritized


class RemediationAgent:
    def __init__(self, db_client, llm_client):
        self.db = db_client
        self.llm = llm_client

    async def execute_task(self, payload: Dict[str, Any]):
        vuln_id = payload.get("vulnerability_id")
        vuln_record: VulnerabilityRecord = await self.db.get_vulnerability(vuln_id)
        
        if not vuln_record:
            logger.error(f"Cannot remediate: Vuln {vuln_id} not found.")
            return

        logger.info(f"Generating Remediation Plan for: {vuln_record.title}")

        # 1. Build the LLM Context
        # We pass exactly what the LLM needs to understand the attack
        context = {
            "title": vuln_record.title,
            "layer": vuln_record.layer,
            "proof_of_concept": vuln_record.proof_of_concept,
            "has_leaked_creds": vuln_record.has_leaked_creds,
            "discovery_source": vuln_record.discovery_source
        }

        # 2. Call the AI to generate the fix
        remediation_data = await self.llm.generate_patch(context)

        # 3. Structure and Save the Plan
        # We explicitly set source to "AI_INFERENCE" to enforce the security 
        # constraint that AI outputs must be distinguishable.
        plan = RemediationPlan(
            vulnerability_id=vuln_id,
            root_cause_analysis=remediation_data["root_cause_analysis"],
            target_tech_stack=remediation_data["target_tech_stack"],
            original_code_snippet=remediation_data["original_code_snippet"],
            patched_code_snippet=remediation_data["patched_code_snippet"],
            patch_type=remediation_data["patch_type"],
            source="AI_INFERENCE" 
        )

        plan_id = await self.db.insert_remediation_plan(plan)
        
        logger.info(f"[+] Remediation Plan generated (Plan ID: {plan_id[:8]}). Awaiting Developer implementation.")
        
        # Note: We DO NOT automatically queue the Retesting Agent here.
        # The system must wait for the human developer to read the plan, 
        # apply the code to their repository, and deploy it to a staging environment.