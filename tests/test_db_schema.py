import os
import pytest
from core.database import DatabaseClient, normalize_source, normalize_status
from core.models import TargetAsset, VulnerabilityRecord, VulnStatus, TaskItem, AgentType

def test_source_normalization_and_constraints():
    # Strict schema constraint: source must be 'tool' or 'ai_inference'
    assert normalize_source("TOOL_NMAP") == "tool"
    assert normalize_source("threat_intel") == "tool"
    assert normalize_source("mcp_scanner") == "tool"
    assert normalize_source("AI_INFERENCE") == "ai_inference"
    assert normalize_source("gemini_pro") == "ai_inference"

def test_status_normalization():
    assert normalize_status(VulnStatus.VALIDATED) == "done"
    assert normalize_status(VulnStatus.REMEDIATED) == "done"
    assert normalize_status(VulnStatus.VALIDATING) == "processing"
    assert normalize_status(VulnStatus.UNVALIDATED) == "pending"

def test_schema_file_definitions():
    schema_path = os.path.join(os.path.dirname(__file__), "..", "db", "schema.sql")
    assert os.path.exists(schema_path), "schema.sql must exist in db/"

    with open(schema_path, "r", encoding="utf-8") as f:
        schema_sql = f.read()

    # Verify all 6 core relational tables exist
    required_tables = [
        "CREATE TABLE IF NOT EXISTS assets",
        "CREATE TABLE IF NOT EXISTS findings",
        "CREATE TABLE IF NOT EXISTS validated_findings",
        "CREATE TABLE IF NOT EXISTS attack_paths",
        "CREATE TABLE IF NOT EXISTS remediations",
        "CREATE TABLE IF NOT EXISTS retests",
        "CREATE TABLE IF NOT EXISTS tasks"
    ]
    for tbl in required_tables:
        assert tbl in schema_sql, f"Missing table definition: {tbl}"

    # Verify source constraint is enforced
    assert "source TEXT NOT NULL CHECK (source IN ('tool', 'ai_inference'))" in schema_sql

@pytest.mark.asyncio
async def test_database_client_crud_and_status_transitions():
    db = DatabaseClient()
    
    # 1. Insert Asset
    asset = TargetAsset(asset_identifier="db.internal.net", layer="Database", is_authorized=True)
    asset_id = await db.insert_asset(asset)
    assert asset_id == asset.id
    fetched_asset = await db.get_asset(asset_id)
    assert fetched_asset.asset_identifier == "db.internal.net"

    # 2. Insert Finding
    vuln = VulnerabilityRecord(
        asset_id=asset.id,
        title="SQL Injection in Orders Endpoint",
        criticality_score=8.5,
        layer="Database",
        status=VulnStatus.UNVALIDATED,
        discovery_source="TOOL_NMAP"
    )
    vuln_id = await db.insert_vulnerability(vuln)
    assert vuln_id == vuln.id

    # 3. Status Transition: UNVALIDATED -> VALIDATED
    await db.update_vulnerability(vuln_id, status=VulnStatus.VALIDATED, confidence_score=0.95)
    updated = await db.get_vulnerability(vuln_id)
    assert updated.status == VulnStatus.VALIDATED
    assert updated.confidence_score == 0.95

    # 4. Status Transition: VALIDATED -> REMEDIATED
    await db.update_vulnerability(vuln_id, status=VulnStatus.REMEDIATED, confidence_score=1.0)
    remediated = await db.get_vulnerability(vuln_id)
    assert remediated.status == VulnStatus.REMEDIATED

    # 5. Retest record tracking
    retest_id = await db.record_retest(finding_id=vuln_id, still_vulnerable=False, evidence="Marker suppressed")
    assert retest_id is not None
    retests = await db.get_retests(vuln_id)
    assert len(retests) == 1
    assert retests[0]["still_vulnerable"] is False
