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

async def get_vulnerabilities(status: Optional[VulnStatus] = None, db: DatabaseClient = Depends(get_db)):
    """Fetches all findings. Optionally filter by status (e.g., validated)."""
    return await db.get_vulnerabilities(status=status)


# --- 3. Dashboard: Live Priority Queue (Tasks) ---

@router.get("/queue", response_model=List[TaskItem])
async def trigger_retest(vuln_id: str, db: DatabaseClient = Depends(get_db)):
    """Called by the Frontend when a developer clicks 'Verify Fix'."""
    vuln = await db.get_vulnerability(vuln_id)
    if not vuln:
        raise HTTPException(status_code=404, detail="Vulnerability not found.")
        
    if vuln.status == VulnStatus.REMEDIATED:
        raise HTTPException(status_code=400, detail="Vulnerability is already remediated.")

    logger.info(f"User requested manual retest for Vuln: {vuln_id}")
    
    task = TaskItem(
        target_agent=AgentType.RETEST,
        priority=100, 
        payload={"vulnerability_id": vuln_id}
    )
    task_id = await db.insert_task(task)
    
    return {"message": "Retest triggered successfully.", "task_id": task_id}
@router.get("/session")
