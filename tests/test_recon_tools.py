import pytest
from tools.recon import (
    search_nvd, exploitdb_search, virustotal_lookup, 
    hibp_check, dns_lookup, phishing_score, 
    whois_lookup, mitre_attack_lookup, dir_bruteforce
)

def test_search_nvd_schema():
    res = search_nvd("CVE-2021-44228")
    assert isinstance(res, dict)
    assert res["cve_id"] == "CVE-2021-44228"
    assert isinstance(res["cvss_score"], float)
    assert res["cvss_score"] == 10.0
    assert res["severity"] == "CRITICAL"
    assert isinstance(res["references"], list)
    assert res["source"] == "tool"

def test_exploitdb_search_schema():
    res = exploitdb_search("CVE-2021-44228")
    assert isinstance(res, dict)
    assert res["cve_id"] == "CVE-2021-44228"
    assert res["has_exploit"] is True
    assert res["poc_count"] >= 1
    assert res["source"] == "tool"

def test_virustotal_lookup_schema():
    res = virustotal_lookup("example.com")
    assert isinstance(res, dict)
    assert res["target"] == "example.com"
    assert "detection_ratio" in res
    assert res["source"] == "tool"

def test_hibp_check_privacy_schema():
    res = hibp_check("admin@example.com")
    assert isinstance(res, dict)
    assert res["email"] == "admin@example.com"
    assert isinstance(res["breach_count"], int)
    assert isinstance(res["has_leaked_creds"], bool)
    assert isinstance(res["breaches"], list)
    assert res["source"] == "tool"
    # Ensure no raw password fields exist in the output dictionary
    assert "password" not in res
    assert "raw_credentials" not in res

def test_dns_lookup_schema():
    res = dns_lookup("localhost")
    assert isinstance(res, dict)
    assert "records" in res
    assert "A" in res["records"]
    assert "ssl" in res
    assert res["source"] == "tool"

def test_phishing_score_schema():
    res = phishing_score("paypal-security-account.xyz/login")
    assert isinstance(res, dict)
    assert 0.0 <= res["phishing_score"] <= 10.0
    assert res["risk_level"] in ("LOW", "MEDIUM", "HIGH", "CRITICAL")
    assert isinstance(res["indicators"], list)
    assert res["is_phishing_suspected"] is True
    assert res["source"] == "tool"

def test_whois_lookup_schema():
    res = whois_lookup("example.com")
    assert isinstance(res, dict)
    assert "domain" in res
    assert "registrar" in res
    assert res["source"] == "tool"

def test_mitre_attack_lookup_schema():
    res = mitre_attack_lookup("T1190")
    assert isinstance(res, dict)
    assert res["technique_id"] == "T1190"
    assert res["tactic"] == "Initial Access"
    assert "mitigation" in res
    assert res["source"] == "tool"

def test_dir_bruteforce_schema():
    res = dir_bruteforce("http://localhost:8000")
    assert isinstance(res, dict)
    assert "target_url" in res
    assert "paths_probed" in res
    assert isinstance(res["discovered_endpoints"], list)
    assert res["source"] == "tool"

@pytest.mark.asyncio
async def test_scan_owasp_top10_schema():
    from tools.scanners import scan_owasp_top10
    res = await scan_owasp_top10("portal.test.corp")
    assert isinstance(res, dict)
    assert res["owasp_version"] == "2021"
    assert "categories_covered" in res
    assert len(res["categories_covered"]) == 10
    assert "A01:2021-Broken Access Control" in res["categories_covered"]
    assert "A10:2021-Server-Side Request Forgery (SSRF)" in res["categories_covered"]
    assert "vulnerabilities" in res
    assert isinstance(res["vulnerabilities"], list)
    for v in res["vulnerabilities"]:
        assert "title" in v
        assert "cwe_id" in v
        assert "owasp_category" in v
        assert "test_payload" in v
        assert "expected_marker" in v

