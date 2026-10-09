import pytest
import asyncio
from core.db import DatabaseClient
from core.models import TargetAsset, VulnerabilityRecord, VulnStatus
from agents.attack_path import AttackPathAgent, MockAttackPathCorrelator

@pytest.mark.asyncio
async def test_attack_path_graph_and_bayesian_chokepoint():
    db = DatabaseClient()
    
    # 1. Create Web Asset and Crown Jewel Asset
    web_asset = TargetAsset(
        asset_identifier="portal.target.local",
        layer="Web",
        is_authorized=True,
        metadata={"is_crown_jewel": False}
    )
    jewel_asset = TargetAsset(
        asset_identifier="db-cluster.target.local",
        layer="Database",
        is_authorized=True,
        metadata={"is_crown_jewel": True}
    )
    await db.insert_asset(web_asset)
    await db.insert_asset(jewel_asset)

    # 2. Insert validated chainable vulnerabilities
    vuln_entry = VulnerabilityRecord(
        asset_id=web_asset.id,
        title="Spring4Shell RCE in Public Portal",
        criticality_score=9.5,
        layer="Web",
        status=VulnStatus.VALIDATED,
        discovery_source="tool",
        confidence_score=0.95,
        proof_of_concept="id; whoami",
        metadata={"cve_id": "CVE-2022-22965"}
    )
    
    vuln_internal = VulnerabilityRecord(
        asset_id=jewel_asset.id,
        title="Unauthenticated PostgreSQL Direct Access",
        criticality_score=8.8,
        layer="Database",
        status=VulnStatus.VALIDATED,
        discovery_source="tool",
        confidence_score=0.9,
        proof_of_concept="SELECT * FROM crown_jewel_records;",
        metadata={"cve_id": "CVE-2021-23017"}
    )
    
    await db.insert_vulnerability(vuln_entry)
    await db.insert_vulnerability(vuln_internal)

    # 3. Execute AttackPathAgent
    agent = AttackPathAgent(db_client=db, llm_client=MockAttackPathCorrelator())
    await agent.execute_task({"trigger": "new_vuln_validated"})

    # 4. Verify graph and path persistence
    assert len(db.attack_paths) > 0, "Expected at least one attack path to be generated"
    path = list(db.attack_paths.values())[0]

    # Verify Bayesian probability and chokepoint
    assert 0.0 <= path.path_probability <= 1.0
    assert path.chokepoint_vuln_id in (vuln_entry.id, vuln_internal.id)
    assert path.total_risk_score > 0
    assert len(path.nodes) > 0
    assert len(path.edges) > 0
