import pytest
from core.db import DatabaseClient
from core.models import TargetAsset, VulnerabilityRecord, VulnStatus, AgentType
from agents.validation import ValidationAgent, MockValidationLLM
from report.scorer import posture_scorer
from tests.test_safety import *

@pytest.mark.asyncio
async def test_validation_agent_differentiates_exploits_and_false_positives():
    """
    Verifies that the Validation Agent correctly proves valid exploitability for real vulnerabilities
    while identifying and isolating false positives (defended, patched, or non-exploitable findings).
    """
    db = DatabaseClient()
    asset = TargetAsset(
        asset_identifier="portal.test.corp",
        layer="Web",
        is_authorized=True
    )
    await db.insert_asset(asset)

    # 1. An exploitable SQL Injection vulnerability (will trigger syntax error in sandbox)
    sqli_vuln = VulnerabilityRecord(
        asset_id=asset.id,
        title="Potential SQL Injection in query parameter (CWE-89)",
        criticality_score=8.8,
        layer="Web",
        status=VulnStatus.UNVALIDATED,
        discovery_source="TOOL_WEB_SCANNER"
    )
    sqli_id = await db.insert_vulnerability(sqli_vuln)

    # 2. A false positive / patched finding (OpenSSH scp disabled or WAF-protected)
    ssh_vuln = VulnerabilityRecord(
        asset_id=asset.id,
        title="Potential CVE-2020-15778 in OpenSSH 8.2p1",
        criticality_score=7.8,
        layer="Network",
        status=VulnStatus.UNVALIDATED,
        discovery_source="TOOL_EVIDENCE"
    )
    ssh_id = await db.insert_vulnerability(ssh_vuln)

    # 3. Another false positive finding (XSS blocked by output encoding)
    xss_vuln = VulnerabilityRecord(
        asset_id=asset.id,
        title="Potential Reflected XSS in search parameter (CWE-79)",
        criticality_score=7.2,
        layer="Web",
        status=VulnStatus.UNVALIDATED,
        discovery_source="TOOL_WEB_SCANNER"
    )
    xss_id = await db.insert_vulnerability(xss_vuln)

    # 4. An exploitable Nginx Memory Overwrite / LFI vulnerability
    lfi_vuln = VulnerabilityRecord(
        asset_id=asset.id,
        title="Potential CVE-2021-23017 in NGINX",
        criticality_score=8.1,
        layer="Network",
        status=VulnStatus.UNVALIDATED,
        discovery_source="TOOL_EVIDENCE"
    )
    lfi_id = await db.insert_vulnerability(lfi_vuln)

    # Execute ValidationAgent on all 4 findings
    val_agent = ValidationAgent(db_client=db, llm_client=MockValidationLLM())
    await val_agent.execute_task({"vulnerability_id": sqli_id})
    await val_agent.execute_task({"vulnerability_id": ssh_id})
    await val_agent.execute_task({"vulnerability_id": xss_id})
    await val_agent.execute_task({"vulnerability_id": lfi_id})

    # Retrieve updated records from DB
    updated_sqli = await db.get_vulnerability(sqli_id)
    updated_ssh = await db.get_vulnerability(ssh_id)
    updated_xss = await db.get_vulnerability(xss_id)
    updated_lfi = await db.get_vulnerability(lfi_id)

    # Verify Exploited vs False Positive distribution
    assert updated_sqli.status == VulnStatus.VALIDATED, f"SQLi should be VALIDATED, got {updated_sqli.status}"
    assert updated_lfi.status == VulnStatus.VALIDATED, f"LFI should be VALIDATED, got {updated_lfi.status}"
    assert updated_ssh.status == VulnStatus.FALSE_POSITIVE, f"OpenSSH should be FALSE_POSITIVE, got {updated_ssh.status}"
    assert updated_xss.status == VulnStatus.FALSE_POSITIVE, f"XSS should be FALSE_POSITIVE, got {updated_xss.status}"

    # Verify downstream tasks:
    # Only VALIDATED findings trigger Attack Path and Remediation tasks
    attack_tasks = [t for t in db.tasks.values() if t.target_agent == AgentType.ATTACK_PATH]
    remed_tasks = [t for t in db.tasks.values() if t.target_agent == AgentType.REMEDIATION]
    remed_vuln_ids = [t.payload.get("vulnerability_id") for t in remed_tasks]

    assert len(attack_tasks) == 2, f"Expected 2 attack path tasks triggered, found {len(attack_tasks)}"
    assert sqli_id in remed_vuln_ids
    assert lfi_id in remed_vuln_ids
    assert ssh_id not in remed_vuln_ids, "False positive should not trigger remediation"
    assert xss_id not in remed_vuln_ids, "False positive should not trigger remediation"

@pytest.mark.asyncio
async def test_posture_score_excludes_false_positives():
    """Verifies that false positives do not penalize the defensive posture score."""
    db = DatabaseClient()
    asset = TargetAsset(asset_identifier="app.test.corp", layer="Web", is_authorized=True)
    await db.insert_asset(asset)

    fp_vuln = VulnerabilityRecord(
        asset_id=asset.id,
        title="Unexploitable XSS",
        criticality_score=9.5,
        layer="Web",
        status=VulnStatus.FALSE_POSITIVE,
        discovery_source="tool"
    )
    await db.insert_vulnerability(fp_vuln)

    snapshot = {
        "assets": [asset.dict()],
        "vulnerabilities": [fp_vuln.dict()],
        "attack_paths": [],
        "retests": []
    }
    score = posture_scorer(snapshot)
    assert score["false_positives_count"] == 1
    assert score["validated_findings_count"] == 0
    # A single false positive with zero validated findings should not degrade grade to F
    assert score["posture_grade"] in ("A", "B")

@pytest.mark.asyncio
async def test_validation_agent_validates_vapt_discovered_vulnerabilities():
    """
    Verifies that the Validation Agent receives context from the VAPT agent's discovery tasks
    and successfully validates genuine exploitable vulnerabilities while marking defenses as false positives.
    """
    from agents.vapt import VAPTAgent, MockLLMClient
    db = DatabaseClient()
    asset = TargetAsset(
        asset_identifier="portal.test.corp",
        layer="Web",
        is_authorized=True
    )
    await db.insert_asset(asset)

    # 1. Run VAPT discovery
    vapt_agent = VAPTAgent(db_client=db, llm_client=MockLLMClient())
    await vapt_agent.execute_task({"asset_id": asset.id})

    # Ensure findings and validation tasks were queued
    assert len(db.vulnerabilities) > 0
    val_tasks = [t for t in db.tasks.values() if t.target_agent == AgentType.VALIDATION]
    assert len(val_tasks) > 0

    # 2. Run ValidationAgent on all queued tasks
    val_agent = ValidationAgent(db_client=db, llm_client=MockValidationLLM())
    for task in val_tasks:
        await val_agent.execute_task(task.payload)

    # 3. Check status of validated vulnerabilities
    validated = [v for v in db.vulnerabilities.values() if v.status == VulnStatus.VALIDATED]
    false_positives = [v for v in db.vulnerabilities.values() if v.status == VulnStatus.FALSE_POSITIVE]

    assert len(validated) > 0, "Validation agent must successfully validate exploitable vulnerabilities"
    assert len(false_positives) > 0, "Validation agent must correctly isolate false positives"
    # Ensure no findings remain stuck in UNVALIDATED
    unvalidated = [v for v in db.vulnerabilities.values() if v.status == VulnStatus.UNVALIDATED]
    assert len(unvalidated) == 0, "All queued vulnerabilities should be processed"

