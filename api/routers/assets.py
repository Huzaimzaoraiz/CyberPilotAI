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

async def get_assets(db: DatabaseClient = Depends(get_db)):
    """Fetches all registered target assets."""
    return await db.get_all_assets()
