import pytest
from core.database import DatabaseClient
from core.models import TargetAsset, VulnStatus, AgentType
from agents.vapt import VAPTAgent, MockLLMClient
from tools.scanners import run_nmap

@pytest.mark.asyncio
async def test_vapt_unauthorized_target_aborted():
    db = DatabaseClient()
    unauth_asset = TargetAsset(
        asset_identifier="unauthorized-domain.com",
        layer="Web",
        is_authorized=False
    )
    await db.insert_asset(unauth_asset)

    vapt_agent = VAPTAgent(db_client=db, llm_client=MockLLMClient())
    await vapt_agent.execute_task({"asset_id": unauth_asset.id})

    # Should not produce any vulnerabilities or queue any tasks
    assert len(db.vulnerabilities) == 0
    assert len(db.tasks) == 0

@pytest.mark.asyncio
async def test_nmap_scan_output_format():
    output = await run_nmap("localhost")
    assert isinstance(output, str)
    assert "PORT" in output
    assert "STATE" in output
    assert "SERVICE" in output

@pytest.mark.asyncio
async def test_vapt_authorized_target_discovery_flow():
    db = DatabaseClient()
    auth_asset = TargetAsset(
        asset_identifier="authorized-test.corp",
        layer="Web",
        is_authorized=True
    )
    await db.insert_asset(auth_asset)

    vapt_agent = VAPTAgent(db_client=db, llm_client=MockLLMClient())
    await vapt_agent.execute_task({"asset_id": auth_asset.id})

    # Verify vulnerabilities were discovered and queued
    assert len(db.vulnerabilities) > 0
    for v in db.vulnerabilities.values():
        assert v.status == VulnStatus.UNVALIDATED
        assert v.asset_id == auth_asset.id

    # Verify validation tasks were placed in queue
    val_tasks = [t for t in db.tasks.values() if t.target_agent == AgentType.VALIDATION]
    assert len(val_tasks) > 0
