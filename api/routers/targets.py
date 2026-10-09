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

class TargetCreateRequest(BaseModel):
    domain_or_ip: str
    layer: str = "Web"
    is_authorized: bool  # Explicit human verification check
    is_crown_jewel: bool = False
    include_simulated_crown_jewel: bool = False


# --- 1. Dynamic Ingestion: Add Target Asset ---

@router.post("/targets", response_model=Dict[str, str])
async def create_target_and_start_scan(req: TargetCreateRequest, db: DatabaseClient = Depends(get_db)):
    """Dynamically ingests a new target website and kicks off the VAPT agent."""
    if not req.is_authorized:
        raise HTTPException(
            status_code=403, 
            detail="Active testing requires explicit authorization confirmation."
        )

    # 1. Store Target Asset
    metadata = {"is_crown_jewel": True} if req.is_crown_jewel else {}
    asset = TargetAsset(
        asset_identifier=req.domain_or_ip,
        layer=req.layer,
        is_authorized=req.is_authorized,
        metadata=metadata
    )
    asset_id = await db.insert_asset(asset)

    # Initialize / Update Scan Session for real-time stopwatch & status
    from datetime import datetime, timezone
    db.scan_session = {
        "is_active": True,
        "started_at": datetime.now(timezone.utc).isoformat(),
        "completed_at": None,
        "target": req.domain_or_ip
    }

    # Optionally seed simulated internal crown jewel if requested and none exists
    if req.include_simulated_crown_jewel and not req.is_crown_jewel:
        existing_jewel = next((a for a in db.assets.values() if a.metadata.get("is_crown_jewel")), None)
        if not existing_jewel:
            crown_jewel = TargetAsset(
                asset_identifier="10.0.0.54 (Internal DB & Vault)",
                layer="Network",
                is_authorized=True,
                metadata={"is_crown_jewel": True}
            )
            await db.insert_asset(crown_jewel)

    # 2. Trigger VAPT Scan Task
    task = TaskItem(
        target_agent=AgentType.VAPT,
        priority=30,  # Initial recon priority
        payload={"asset_id": asset_id}
    )
    task_id = await db.insert_task(task)

    # 3. Trigger Threat Intel Task for domain assets
    if req.layer in ["Web", "Cloud"] or any(c.isalpha() for c in req.domain_or_ip):
        await db.insert_task(
            TaskItem(
                target_agent=AgentType.THREAT_INTEL,
                priority=25,
                payload={"asset_id": asset_id}
            )
        )

    return {
        "message": f"Scan initiated for {req.domain_or_ip}", 
        "asset_id": asset_id, 
        "task_id": task_id
    }


# --- 2. Dashboard: Monitored Assets ---

@router.get("/assets", response_model=List[TargetAsset])
@router.get("/targets", response_model=List[TargetAsset])
