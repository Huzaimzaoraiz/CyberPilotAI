from fastapi import APIRouter, HTTPException, Depends, Request
from typing import List, Dict, Any, Optional
from pydantic import BaseModel, HttpUrl
import logging

from core.models import (
    TargetAsset, VulnerabilityRecord, TaskItem, 
    AttackPath, RemediationPlan, AgentType, VulnStatus
)
from core.db import DatabaseClient

logger = logging.getLogger("API")

def get_db(request: Request):
    return request.app.state.db

router = APIRouter()

class SASTScanRequest(BaseModel):
    target: str  # Code snippet or file path
    language: Optional[str] = None

class WebScanRequest(BaseModel):
    url: str
    check_injection: bool = True

@router.post("/scanners/sast")
async def run_sast_scan(req: SASTScanRequest):
    """Executes on-demand Static Application Security Testing for SQLi, XSS, and OWASP Top 10."""
    from tools.scanners import scan_code_sast
    findings = await scan_code_sast(req.target)
    return {
        "target": req.target[:80] + "..." if len(req.target) > 80 else req.target,
        "findings_count": len(findings),
        "findings": findings
    }

@router.post("/scanners/web")
async def run_web_scan(req: WebScanRequest):
    """Executes on-demand web audit for SQLi, XSS, headers, and CORS."""
    from tools.scanners import scan_web_vulnerabilities
    findings = await scan_web_vulnerabilities(req.url)
    return {
        "url": req.url,
        "findings_count": len(findings),
        "findings": findings
    }

# --- 9. Assessment Report Generation & Export ---

