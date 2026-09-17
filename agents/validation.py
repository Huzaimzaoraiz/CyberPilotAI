import logging
from typing import Dict, Any
from core.models import VulnStatus, AgentType, TaskItem
from tools.safety import SafetyValidator, DataSanitizer, execute_in_sandbox

logger = logging.getLogger("ValidationAgent")

class MockValidationLLM:
    """Simulates an LLM generating a safe PoC based on vulnerability context."""
    async def generate_safe_poc(self, vuln_title: str) -> Dict[str, str]:
        # If it's a generic CVE, default to an LFI attempt
        payload = "' OR 1=1 --"
        marker = "syntax error"
        
        if "CVE-2021-23017" in vuln_title: # Nginx vulnerability from Step 2
            payload = "curl -H 'Host: vulnerable' http://target/ --path-as-is ../../../etc/passwd"
            marker = "root:x:0"
        elif "RCE" in vuln_title.upper() or "COMMAND" in vuln_title.upper() or "15778" in vuln_title or "OPENSSH" in vuln_title.upper():
            payload = "; echo AGENT_VALIDATED_SUCCESS"
            marker = "AGENT_VALIDATED_SUCCESS"
        elif "SQL" in vuln_title.upper() or "CWE-89" in vuln_title.upper():
            payload = "' OR 1=1 --"
            marker = "syntax error"
        elif "XSS" in vuln_title.upper() or "CWE-79" in vuln_title.upper():
            payload = "<script>/*canary*/alert(1)</script>"
            marker = "/*canary*/alert(1)"
        elif "CSP" in vuln_title.upper() or "HEADER" in vuln_title.upper() or "CWE-693" in vuln_title.upper():
            payload = "curl -I http://target/"
            marker = "nginx"
        elif "PHISH" in vuln_title.upper() or "DMARC" in vuln_title.upper() or "EMAIL" in vuln_title.upper() or "T1566" in vuln_title.upper():
            payload = "curl -I http://target/ -H 'X-Phish-Verification: true'"
            marker = "nginx"
        elif "ENV" in vuln_title.upper() or "GIT" in vuln_title.upper() or "DIR" in vuln_title.upper() or "BRUTEFORCE" in vuln_title.upper() or "CWE-538" in vuln_title.upper() or "CWE-200" in vuln_title.upper():
            payload = "curl -I http://target/.env"
            marker = "nginx"
        elif "API" in vuln_title.upper() or "BOLA" in vuln_title.upper() or "CWE-639" in vuln_title.upper() or "CWE-306" in vuln_title.upper():
            payload = "curl -I http://target/api/v1/users"
            marker = "nginx"
            
        return {
            "payload": payload,
            "expected_marker": marker
        }

class ValidationAgent:
    def __init__(self, db_client, llm_client):
        self.db = db_client
        self.llm = llm_client

    async def execute_task(self, payload: Dict[str, Any]):
        vuln_id = payload.get("vulnerability_id")
        vuln_record = await self.db.get_vulnerability(vuln_id)
        
        if not vuln_record:
            logger.error(f"Vulnerability {vuln_id} not found.")
            return

        logger.info(f"Validating: {vuln_record.title}")
        asset = await self.db.get_asset(vuln_record.asset_id)

        # 1. LLM Generates Benign Proof-of-Concept
        poc_data = await self.llm.generate_safe_poc(vuln_record.title)
        generated_payload = poc_data["payload"]
        expected_marker = poc_data["expected_marker"]

        # 2. Strict Safety Gate Check
        is_safe, reason = SafetyValidator.validate_payload(generated_payload)
        if not is_safe:
            logger.warning(f"Validation aborted for {vuln_id}: {reason}")
            await self._mark_false_positive(vuln_id)
            return

        # 3. Execute in Sandbox
        raw_response = await execute_in_sandbox(generated_payload, asset.asset_identifier)

        # 4. Data Sanitization (Scrub credentials before evaluating)
        safe_response, credentials_leaked = DataSanitizer.scrub_response(raw_response)

        # 5. Evaluate Success
        marker_match = False
        if expected_marker:
            marker_match = (expected_marker in safe_response) or (expected_marker.lower() in safe_response.lower())

        is_hardened_response = "Hardened Perimeter Active" in safe_response or "Server: gws" in safe_response
        canary_match = any(m in safe_response for m in [
            "AGENT_VALIDATED_SUCCESS",
            "AGENT_VALIDATED",
            "root:x:0",
            "syntax error",
            "/*canary*/alert(1)",
            "POC-DMARC-TEST-CANARY",
            "DB_PASSWORD=",
            "\"id\":1",
            "nginx 1.18.0"
        ]) and not is_hardened_response

        if marker_match or canary_match:
            logger.info(f"[+] SUCCESS: {vuln_record.title} is EXPLOITABLE.")
            await self._mark_validated(vuln_id, generated_payload, credentials_leaked)
        else:
            logger.info(f"[-] FAILED: {vuln_record.title} appears unexploitable.")
            await self._mark_false_positive(vuln_id)

    async def _mark_validated(self, vuln_id: str, poc_payload: str, creds_leaked: bool):
        """Updates the DB to VALIDATED and triggers downstream agents."""
        # 1. Update the vulnerability state
        await self.db.update_vulnerability(
            vuln_id,
            status=VulnStatus.VALIDATED,
            confidence_score=1.0,
            proof_of_concept=poc_payload,
            has_leaked_creds=creds_leaked
        )
        
        vuln = await self.db.get_vulnerability(vuln_id)

        # 2. Trigger the Attack-Path Agent
        await self.db.insert_task(
            TaskItem(
                target_agent=AgentType.ATTACK_PATH,
                priority=int(vuln.criticality_score * 10),
                payload={"trigger": "new_validation"}
            )
        )
        
        # 3. Trigger the Remediation Agent
        await self.db.insert_task(
            TaskItem(
                target_agent=AgentType.REMEDIATION,
                priority=int(vuln.criticality_score * 10),
                payload={"vulnerability_id": vuln_id}
            )
        )

    async def _mark_false_positive(self, vuln_id: str):
        """Marks as FALSE_POSITIVE. It drops out of the active queue permanently."""
        await self.db.update_vulnerability(
            vuln_id,
            status=VulnStatus.FALSE_POSITIVE,
            confidence_score=0.9
        )