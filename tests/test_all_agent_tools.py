import pytest
import json
import networkx as nx
from tools.recon import (
    search_nvd, exploitdb_search, virustotal_lookup, hibp_check,
    dns_lookup, phishing_score, whois_lookup, mitre_attack_lookup, dir_bruteforce
)
from tools.scanners import (
    port_scanner, service_fingerprint, web_crawler,
    header_analyzer, ssl_checker, api_endpoint_scanner, scan_owasp_top10
)
from agents.validation import cve_verifier, exploitability_scorer, safe_probe
from agents.attack_path import graph_builder, path_ranker, break_chain_analyzer, mitre_mapper
from agents.remediation import root_cause_analyzer, fix_generator, patch_prioritizer
from agents.retesting import retest_probe, verification_reporter
from report.exporter import report_exporter
from report.scorer import posture_scorer
from report.graph import attack_graph_renderer
from core.models import VulnerabilityRecord, TargetAsset, VulnStatus

# --- 1. Standalone Reconnaissance Tools Tests ---

def test_standalone_recon_tools():
    nvd = search_nvd("CVE-2021-44228")
    assert nvd["cvss_score"] == 10.0
    assert nvd["severity"] == "CRITICAL"

    edb = exploitdb_search("CVE-2021-44228")
    assert edb["has_exploit"] is True
    assert edb["poc_count"] >= 1

    vt = virustotal_lookup("example.com")
    assert "detection_ratio" in vt

    hibp = hibp_check("user@example.com")
    assert "password" not in hibp
    assert isinstance(hibp["breach_count"], int)

    dns = dns_lookup("localhost")
    assert "records" in dns

    phish = phishing_score("paypal-account-verify.xyz/login")
    assert phish["is_phishing_suspected"] is True

    who = whois_lookup("example.com")
    assert "domain" in who

    mitre = mitre_attack_lookup("T1190")
    assert mitre["technique_id"] == "T1190"

# --- 2. VAPT Agent Tools Tests ---

@pytest.mark.asyncio
async def test_vapt_port_scanner_and_fingerprint():
    scan_res = await port_scanner("localhost")
    assert "PORT" in scan_res
    assert "STATE" in scan_res

    fp_res = await service_fingerprint("localhost")
    assert "banners" in fp_res
    assert "ports_checked" in fp_res

@pytest.mark.asyncio
async def test_vapt_web_crawler_detects_sqli_and_xss():
    """Verifies that web_crawler crawls endpoints, forms, and detects both SQLi and XSS."""
    crawl_res = await web_crawler("portal.test.corp")
    assert crawl_res["endpoints_discovered"] >= 1
    assert len(crawl_res["vulnerabilities"]) >= 2

    vuln_cwes = [v["cwe_id"] for v in crawl_res["vulnerabilities"]]
    assert "CWE-89" in vuln_cwes, "Web crawler must detect SQL Injection"
    assert "CWE-79" in vuln_cwes, "Web crawler must detect Cross-Site Scripting (XSS)"

    # Verify payloads and expected markers are attached
    for v in crawl_res["vulnerabilities"]:
        assert "test_payload" in v
        assert "expected_marker" in v

@pytest.mark.asyncio
async def test_vapt_header_analyzer_and_ssl_checker():
    h_res = await header_analyzer("http://localhost:8000")
    assert "missing_security_headers" in h_res or "vulnerabilities" in h_res

    ssl_res = await ssl_checker("insecure-portal.test.corp")
    assert "vulnerabilities" in ssl_res
    assert len(ssl_res["vulnerabilities"]) >= 1
    assert ssl_res["vulnerabilities"][0]["cwe_id"] == "CWE-319"

# --- 3. Validation Agent Tools Tests ---

def test_validation_cve_verifier_and_scorer():
    ver = cve_verifier("Log4Shell vulnerability", "CVE-2021-44228")
    assert ver["is_known_cve"] is True
    assert ver["has_public_poc"] is True

    score = exploitability_scorer("CVE-2021-44228", {"criticality_score": 10.0, "reachability": "network"})
    assert 0.8 <= score <= 1.0

@pytest.mark.asyncio
async def test_validation_safe_probe():
    probe_res = await safe_probe("portal.test.corp", "SQL Injection", "' OR '1'='1' --")
    assert probe_res["is_confirmed"] is True
    assert probe_res["credentials_leaked"] is False
    assert "response_evidence" in probe_res

# --- 4. Attack-Path Agent Tools Tests ---

def test_attack_path_tools():
    v1 = VulnerabilityRecord(
        asset_id="asset-1",
        title="SQL Injection in parameter (CWE-89)",
        criticality_score=8.9,
        layer="Web",
        discovery_source="tool",
        status=VulnStatus.VALIDATED
    )
    v2 = VulnerabilityRecord(
        asset_id="asset-2",
        title="Outdated Component (CVE-2021-23017)",
        criticality_score=8.1,
        layer="Network",
        discovery_source="tool",
        status=VulnStatus.VALIDATED
    )
    jewel = TargetAsset(
        asset_identifier="db-crown-jewel",
        layer="Network",
        is_authorized=True,
        metadata={"is_crown_jewel": True}
    )
    v2.asset_id = jewel.id

    graph = graph_builder([v1, v2], [jewel])
    assert "INTERNET" in graph
    assert f"VULN:{v1.id}" in graph

    ranked = path_ranker(graph)
    assert len(ranked) >= 1

    choke = break_chain_analyzer(graph)
    assert "chokepoint_node" in choke

    mapped = mitre_mapper("SQL Injection CWE-89")
    assert mapped["technique_id"] == "T1190"

# --- 5. Remediation Agent Tools Tests ---

def test_remediation_tools():
    finding = {"title": "SQL Injection in parameter 'artist' (CWE-89)", "criticality_score": 8.9}
    root = root_cause_analyzer(finding)
    assert "parameter binding" in root or "parameterized" in root or "database" in root

    fix = fix_generator(finding)
    assert fix["patch_type"] == "code"
    assert "%s" in fix["fix"] or "parameter" in fix["guidance"]

    prioritized = patch_prioritizer([{"chokepoint_node": "VULN:test-id"}], [{"id": "test-id", "title": "SQLi", "criticality_score": 8.9}])
    assert len(prioritized) == 1
    assert prioritized[0]["is_strategic_chokepoint"] is True

# --- 6. Retest Agent Tools Tests ---

@pytest.mark.asyncio
async def test_retest_tools():
    vuln = VulnerabilityRecord(
        asset_id="test",
        title="SQL Injection",
        criticality_score=8.9,
        layer="Web",
        discovery_source="tool",
        proof_of_concept="' OR '1'='1' --"
    )
    is_patched, evidence = await retest_probe("portal.test.corp", vuln)
    rep = verification_reporter(vuln, (is_patched, evidence))
    assert "status" in rep
    assert "verification_evidence" in rep

# --- 7. Report / Dashboard Tools Tests ---

def test_report_tools():
    snapshot = {
        "assets": [{"id": "a1", "asset_identifier": "test.corp", "layer": "Web", "is_authorized": True}],
        "vulnerabilities": [],
        "attack_paths": [],
        "retests": []
    }
    json_bytes = report_exporter(snapshot, "json")
    assert len(json_bytes) > 10
    parsed = json.loads(json_bytes.decode("utf-8"))
    assert "assessment_meta" in parsed

    pdf_bytes = report_exporter(snapshot, "pdf")
    assert len(pdf_bytes) > 200
    assert pdf_bytes.startswith(b"%PDF")

    score = posture_scorer(snapshot)
    assert "posture_score" in score
    assert "posture_grade" in score
