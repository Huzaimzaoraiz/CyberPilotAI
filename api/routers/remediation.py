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

async def get_remediation_plan(vuln_id: str, db: DatabaseClient = Depends(get_db)):
    """Fetches the AI-generated code patch for a specific vulnerability."""
    plan = next((p for p in db.remediations.values() if p.vulnerability_id == vuln_id), None)
    if not plan:
        raise HTTPException(status_code=404, detail="Remediation plan not found or not yet generated.")
    return plan


# --- 6. Developer Action: Trigger Retest ---

@router.post("/retest/{vuln_id}")
