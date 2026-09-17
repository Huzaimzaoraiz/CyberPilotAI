import pytest
from core.database import DatabaseClient
from core.models import TargetAsset, VulnerabilityRecord, VulnStatus, AgentType, RemediationPlan
from agents.retesting import RetestingAgent, MockRetestEvaluator
from agents.remediation import RemediationAgent, MockLLMClient

@pytest.mark.asyncio
async def test_retest_success_transitions_to_remediated_and_queues_attack_path():
    db = DatabaseClient()

    # Setup Asset and Validated Vulnerability
    asset = TargetAsset(
        asset_identifier="app.example.com",
        layer="Web",
        is_authorized=True
    )
    await db.insert_asset(asset)

    vuln = VulnerabilityRecord(
        asset_id=asset.id,
        title="Command Injection in Report Generator",
        criticality_score=9.0,
        layer="Web",
        status=VulnStatus.VALIDATED,
        discovery_source="tool",
        proof_of_concept="; echo 'AGENT_VALIDATED_SUCCESS'"
    )
    await db.insert_vulnerability(vuln)

    # Remediation agent produces plan
    remediation_agent = RemediationAgent(db_client=db, llm_client=MockLLMClient())
    await remediation_agent.execute_task({"vulnerability_id": vuln.id})
    assert len(db.remediations) == 1

    # Custom evaluator that simulates fix applied (suppresses exploit marker)
    class FixedEvaluator:
        async def evaluate_fix(self, original_poc: str, raw_response: str):
            return True, "Exploit payload safely blocked."

    retesting_agent = RetestingAgent(db_client=db, evaluator_client=FixedEvaluator())
    await retesting_agent.execute_task({"vulnerability_id": vuln.id})

    # Verify status transition to REMEDIATED
    updated_vuln = await db.get_vulnerability(vuln.id)
    assert updated_vuln.status == VulnStatus.REMEDIATED
    assert updated_vuln.confidence_score == 1.0

    # Verify that an ATTACK_PATH update was scheduled with priority 100
    attack_path_tasks = [
        t for t in db.tasks.values() 
        if t.target_agent == AgentType.ATTACK_PATH and t.priority == 100
    ]
    assert len(attack_path_tasks) >= 1
    assert attack_path_tasks[0].payload.get("trigger") == "remediation_success"

    # Verify retest was recorded
    retests = await db.get_retests(vuln.id)
    assert len(retests) >= 1
    assert retests[0]["still_vulnerable"] is False
