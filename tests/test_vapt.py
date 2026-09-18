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

@pytest.mark.asyncio
async def test_vapt_dynamic_discovery_different_sites():
    """Verifies that vulnerability detection counts adapt to the target surface instead of a fixed 14."""
    # Target 1: Web application target
    db1 = DatabaseClient()
    asset1 = TargetAsset(
        asset_identifier="portal.test.corp",
        layer="Web",
        is_authorized=True
    )
    await db1.insert_asset(asset1)
    agent1 = VAPTAgent(db_client=db1, llm_client=MockLLMClient())
    await agent1.execute_task({"asset_id": asset1.id})
    count1 = len(db1.vulnerabilities)

    # Target 2: Internal database / vault asset (Network layer, no web surface)
    db2 = DatabaseClient()
    asset2 = TargetAsset(
        asset_identifier="10.0.0.54",
        layer="Network",
        is_authorized=True,
        metadata={"is_crown_jewel": True}
    )
    await db2.insert_asset(asset2)
    agent2 = VAPTAgent(db_client=db2, llm_client=MockLLMClient())
    await agent2.execute_task({"asset_id": asset2.id})
    count2 = len(db2.vulnerabilities)

    # Counts must be dynamic and vary based on asset layer and surface
    assert count1 > 0
    assert count2 > 0
    assert count1 != count2, f"Target counts should vary based on surface (got {count1} vs {count2})"
