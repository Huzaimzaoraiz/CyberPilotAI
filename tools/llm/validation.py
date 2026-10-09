import os
import json
import logging
import asyncio
from typing import Dict, Any, List, Optional, Tuple
from pydantic import BaseModel
import google.generativeai as genai

logger = logging.getLogger("LLM_Engine")

class ValidationLLMMixin:
    async def generate_safe_poc(self, vuln_title: str, vuln_context: Dict[str, Any] = None) -> Dict[str, str]:
        logger.info(f"[LLM] Crafting safe PoC for {vuln_title}...")
        ctx_info = ""
        if vuln_context:
            if vuln_context.get("test_payload") and vuln_context.get("expected_marker"):
                return {
                    "payload": str(vuln_context["test_payload"]),
                    "expected_marker": str(vuln_context["expected_marker"])
                }
            ctx_info = f"\nContext details: {json.dumps(vuln_context)}"

        prompt = f"""
        You are a penetration testing AI. Generate a completely safe, benign 
        Proof-of-Concept payload for this vulnerability: {vuln_title}{ctx_info}
        
        Rules:
        - NEVER use destructive commands (rm, drop, delete, update).
        - Use simple observability markers (e.g., 'echo AGENT_VALIDATED', or reading /etc/passwd, or harmless canary reflection).
        - Respond ONLY with a JSON object with keys 'payload' and 'expected_marker'.
        Example: {{"payload": "curl -H 'Host: vulnerable' http://target/etc/passwd", "expected_marker": "root:x:0"}}
        """
        data = await self._execute_with_fallback(prompt, response_format={"type": "json_object"}, temperature=0.2)
        if data and isinstance(data, dict) and data.get("payload"):
            return {"payload": data.get("payload", ""), "expected_marker": data.get("expected_marker", "")}
        
        # Deterministic fallbacks
        vuln_lower = vuln_title.lower()
        if "sql" in vuln_lower or "sqli" in vuln_lower or "cwe-89" in vuln_lower:
            return {
                "payload": "' OR '1'='1' --",
                "expected_marker": "syntax error near 'OR 1=1'"
            }
        elif "xss" in vuln_lower or "script" in vuln_lower or "cwe-79" in vuln_lower:
            return {
                "payload": "<script>/*canary*/alert(1)</script>",
                "expected_marker": "<script>/*canary*/alert(1)</script>"
            }
        elif "23017" in vuln_lower or "nginx" in vuln_lower or "lfi" in vuln_lower or "cwe-22" in vuln_lower:
            return {
                "payload": "curl -H 'Host: vulnerable' http://target/ --path-as-is ../../../etc/passwd",
                "expected_marker": "root:x:0"
            }
        elif "15778" in vuln_lower or "openssh" in vuln_lower or "scp" in vuln_lower:
            return {
                "payload": "scp -q target:`echo AGENT_VALIDATED` /dev/null",
                "expected_marker": "AGENT_VALIDATED_SUCCESS"
            }
        elif "rce" in vuln_lower or "command" in vuln_lower or "cwe-78" in vuln_lower:
            return {
                "payload": "; echo AGENT_VALIDATED_SUCCESS",
                "expected_marker": "AGENT_VALIDATED_SUCCESS"
            }
        elif any(k in vuln_lower for k in ["env", "git", "dir", "bruteforce", "cwe-538", "cwe-200"]):
            return {
                "payload": "curl -I http://target/.env",
                "expected_marker": "DB_PASSWORD="
            }
        elif any(k in vuln_lower for k in ["api", "auth", "bola", "idor", "cwe-639", "cwe-306"]):
            return {
                "payload": "curl -I http://target/api/v1/users",
                "expected_marker": '"id":'
            }
        elif any(k in vuln_lower for k in ["phish", "dmarc", "spf", "email", "t1566"]):
            return {
                "payload": "curl -I http://target/ -H 'X-Phish-Verification: true'",
                "expected_marker": "DMARC_POLICY_ABSENT"
            }
        elif any(k in vuln_lower for k in ["csp", "header", "cwe-693"]):
            return {
                "payload": "curl -I http://target/",
                "expected_marker": "NO_SECURITY_HEADERS_FOUND"
            }
        return {
            "payload": "' OR 1=1 --",
            "expected_marker": "syntax error"
        }

    # --- 3. Attack Path Agent Ability ---
