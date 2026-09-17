import pytest
from fastapi.testclient import TestClient
from main import app

@pytest.fixture(scope="module")
def client():
    with TestClient(app) as c:
        yield c

def test_target_unauthorized_scope_blocking(client):
    """Scope constraint: Testing without explicit authorization must return 403 Forbidden."""
    payload = {
        "domain_or_ip": "unauthorized-target.com",
        "layer": "Web",
        "is_authorized": False
    }
    resp = client.post("/api/v1/targets", json=payload)
    assert resp.status_code == 403
    assert "explicit authorization" in resp.json()["detail"].lower()

def test_target_ingestion_and_queue(client):
    """Authorized target initiates workflow and registers assets/tasks."""
    payload = {
        "domain_or_ip": "test-authorized.corp",
        "layer": "Web",
        "is_authorized": True,
        "include_simulated_crown_jewel": True
    }
    resp = client.post("/api/v1/targets", json=payload)
    assert resp.status_code == 200
    assert "asset_id" in resp.json()

    # GET /targets
    targets_resp = client.get("/api/v1/targets")
    assert targets_resp.status_code == 200
    assert isinstance(targets_resp.json(), list)
    assert len(targets_resp.json()) >= 1

    # GET /queue
    queue_resp = client.get("/api/v1/queue")
    assert queue_resp.status_code == 200
    assert isinstance(queue_resp.json(), list)

def test_vulnerabilities_and_attack_paths_endpoints(client):
    # GET /vulnerabilities
    vuln_resp = client.get("/api/v1/vulnerabilities")
    assert vuln_resp.status_code == 200
    assert isinstance(vuln_resp.json(), list)

    # GET /attack-paths
    path_resp = client.get("/api/v1/attack-paths")
    assert path_resp.status_code == 200
    assert isinstance(path_resp.json(), list)

def test_report_json_endpoint(client):
    resp = client.get("/api/v1/report/json")
    assert resp.status_code == 200
    data = resp.json()
    assert "assessment_meta" in data
    assert "executive_summary" in data
    assert "posture_metrics" in data
    assert "vulnerability_findings" in data
    assert data["assessment_meta"]["status"] == "COMPLETED"

def test_report_pdf_endpoint(client):
    resp = client.get("/api/v1/report/pdf")
    assert resp.status_code == 200
    assert resp.headers["content-type"] == "application/pdf"
    assert 'attachment; filename="Security_Assessment_Report.pdf"' in resp.headers.get("content-disposition", "")
    assert len(resp.content) > 500  # Non-empty valid PDF bytes

def test_reset_endpoint(client):
    resp = client.post("/api/v1/reset")
    assert resp.status_code == 200
    assert resp.json()["status"] == "success"
