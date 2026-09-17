import logging
from typing import Dict, Any, Tuple
from core.models import VulnerabilityRecord, VulnStatus, TaskItem, AgentType
from tools.safety import execute_in_sandbox

logger = logging.getLogger("RetestingAgent")

class MockRetestEvaluator:
    """Evaluates the server's response to determine if the patch holds."""
    
    async def evaluate_fix(self, original_poc: str, raw_response: str) -> Tuple[bool, str]:
        # If the PoC was command injection, LFI, SQLi, or XSS, check if its marker is suppressed
        exploit_markers = ["AGENT_VALIDATED_SUCCESS", "root:x:0", "syntax error near", "/*canary*/alert(1)"]
        if not any(marker in raw_response for marker in exploit_markers):
            return True, "Payload was successfully blocked or sanitized."
        else:
            return False, "Target is still executing the payload and returning the marker."

class RetestingAgent:
    def __init__(self, db_client, evaluator_client):
        self.db = db_client
        self.evaluator = evaluator_client

    async def execute_task(self, payload: Dict[str, Any]):
        vuln_id = payload.get("vulnerability_id")
        vuln_record: VulnerabilityRecord = await self.db.get_vulnerability(vuln_id)
        
        if not vuln_record or not vuln_record.proof_of_concept:
            logger.error(f"Cannot retest {vuln_id}: Missing original Proof of Concept.")
            return

        logger.info(f"Initiating Post-Fix Retest for: {vuln_record.title}")
        asset = await self.db.get_asset(vuln_record.asset_id)

        # 1. Fire the exact same PoC payload at the target
        raw_response = await execute_in_sandbox(
            payload=vuln_record.proof_of_concept, 
            target=asset.asset_identifier
        )

        # 2. Evaluate the new response
        is_patched, reason = await self.evaluator.evaluate_fix(
            original_poc=vuln_record.proof_of_concept, 
            raw_response=raw_response
        )

        # 3. Handle the State Transition
        if is_patched:
            logger.info(f"[+] SUCCESS: {vuln_record.title} is REMEDIATED. ({reason})")
            
            # Update DB to Remediated status
            await self.db.update_vulnerability(
                vuln_id,
                status=VulnStatus.REMEDIATED,
                confidence_score=1.0
            )
            
            # Trigger Attack-Path Agent to remove this node from the graph
            await self.db.insert_task(
                TaskItem(
                    target_agent=AgentType.ATTACK_PATH,
                    priority=100, # Highest priority to clear the risk off the dashboard
                    payload={"trigger": "remediation_success"}
                )
            )
        else:
            logger.warning(f"[-] FAILURE: Patch for {vuln_record.title} bypassed. ({reason})")
            
            # Revert to Validated and append failure metadata
            await self.db.update_vulnerability(
                vuln_id,
                status=VulnStatus.VALIDATED,
                metadata={"failed_retest_reason": reason}
            )
            
            # Send back to the Remediation Agent to generate a stronger fix
            await self.db.insert_task(
                TaskItem(
                    target_agent=AgentType.REMEDIATION,
                    priority=int(vuln_record.criticality_score * 10),
                    payload={"vulnerability_id": vuln_id, "failure_context": reason}
                )
            )