import os
import json
import logging
import asyncio
from typing import Dict, Any, List, Optional, Tuple
from pydantic import BaseModel
import google.generativeai as genai

logger = logging.getLogger("LLM_Engine")

from .schemas import RemediationSchema

class RemediationLLMMixin:
    async def generate_patch(self, context: Dict[str, Any]) -> Dict[str, Any]:
        logger.info("[LLM] Reverse-engineering payload to generate code patch...")
        
        prompt = f"""
        You are a Senior AppSec Engineer. Analyze this exploited context and generate a fix:
        Context: {json.dumps(context)}
        
        Respond ONLY with a JSON object with keys:
        'root_cause_analysis', 'target_tech_stack', 'original_code_snippet', 'patched_code_snippet', 'patch_type'
        """
        data = await self._execute_with_fallback(prompt, response_format={"type": "json_object"}, temperature=0.3)
        if data and isinstance(data, dict) and data.get("patched_code_snippet"):
            return data
        
        title = context.get("title", "").lower()
        layer = context.get("layer", "")
        
        if "sql" in title or "sqli" in title:
            return {
                "root_cause_analysis": "Untrusted user parameter interpolated directly into SQL query string, enabling arbitrary SQL injection (CWE-89).",
                "target_tech_stack": "SQL / Python Database Driver",
                "original_code_snippet": 'cursor.execute(f"SELECT * FROM users WHERE username = \'{user_input}\'")',
                "patched_code_snippet": 'cursor.execute("SELECT * FROM users WHERE username = %s", (user_input,))',
                "patch_type": "code"
            }
        if "xss" in title or "cross-site scripting" in title:
            return {
                "root_cause_analysis": "User input rendered into HTML document without contextual entity escaping or strict Content Security Policy (CWE-79).",
                "target_tech_stack": "Web Frontend / HTML",
                "original_code_snippet": "document.getElementById('output').innerHTML = userInput;",
                "patched_code_snippet": "document.getElementById('output').textContent = userInput;\n// Recommended Header: Content-Security-Policy: default-src 'self'",
                "patch_type": "code"
            }
        if "header" in title or "csp" in title or "security configuration" in title:
            return {
                "root_cause_analysis": "Missing foundational HTTP security headers exposing application to clickjacking, XSS, and MIME-confusion.",
                "target_tech_stack": "Nginx / Reverse Proxy",
                "original_code_snippet": "# Missing security headers in server block",
                "patched_code_snippet": "add_header Content-Security-Policy \"default-src 'self'\";\nadd_header X-Frame-Options \"DENY\";\nadd_header X-Content-Type-Options \"nosniff\";\nadd_header Strict-Transport-Security \"max-age=31536000; includeSubDomains\" always;",
                "patch_type": "configuration"
            }
        if layer == "OSINT" or context.get("has_leaked_creds"):
            return {
                "root_cause_analysis": "Employee credentials were leaked in a third-party breach, exposing the perimeter.",
                "target_tech_stack": "IAM / Identity Provider",
                "original_code_snippet": "N/A - Configuration Issue",
                "patched_code_snippet": "1. Invalidate all current active sessions.\n2. Force a global password reset.\n3. Enforce MFA (Multi-Factor Authentication) on all external portals.",
                "patch_type": "configuration"
            }
        if "nginx" in title or "23017" in title:
            return {
                "root_cause_analysis": "1-Byte memory overwrite bug in NGINX DNS resolver allows arbitrary code execution.",
                "target_tech_stack": "Nginx / Linux",
                "original_code_snippet": "nginx version: 1.18.0",
                "patched_code_snippet": "sudo apt-get update && sudo apt-get install --only-upgrade nginx",
                "patch_type": "infrastructure"
            }
        if "openssh" in title or "15778" in title or "ssh" in title:
            return {
                "root_cause_analysis": "OpenSSH SCP command execution vulnerability allows command injection through backticks or spaces.",
                "target_tech_stack": "OpenSSH / Linux",
                "original_code_snippet": "scp user@host:path target",
                "patched_code_snippet": "Use sftp or upgrade openssh-client to 8.4p1 or configure StrictHostKeyChecking",
                "patch_type": "configuration"
            }
        return {
            "root_cause_analysis": "Improper input validation or insecure configuration.",
            "target_tech_stack": "Unknown",
            "original_code_snippet": "N/A",
            "patched_code_snippet": "# Please review the affected component and apply vendor security patches.",
            "patch_type": "general"
        }