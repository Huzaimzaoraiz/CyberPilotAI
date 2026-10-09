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

async def get_task_queue(db: DatabaseClient = Depends(get_db)):
    """Fetches the Orchestrator's active and pending tasks, sorted by priority."""
    tasks = list(db.tasks.values())
    active_tasks = [t for t in tasks if t.status in ["pending", "in_progress"]]
    active_tasks.sort(key=lambda x: x.priority, reverse=True)
    return active_tasks


# --- 4. Dashboard: Attack Path Visualizer ---

@router.get("/attack-paths", response_model=List[AttackPath])
