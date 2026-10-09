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

async def get_scan_session(db: DatabaseClient = Depends(get_db)):
    """Fetches scan session metadata, start timestamp, and active status for the stopwatch."""
    session = dict(db.scan_session)
    tasks = list(db.tasks.values())
    active_tasks = [t for t in tasks if t.status in ["pending", "in_progress"]]
    
    # If tasks were scheduled and now none are active, mark as completed
    if session.get("is_active") and len(tasks) > 0 and len(active_tasks) == 0:
        session["is_active"] = False
        if not session.get("completed_at"):
            from datetime import datetime, timezone
            session["completed_at"] = datetime.now(timezone.utc).isoformat()
            db.scan_session["completed_at"] = session["completed_at"]
            db.scan_session["is_active"] = False
            
    session["active_tasks_count"] = len(active_tasks)
    session["total_tasks_count"] = len(tasks)
    return session

@router.post("/reset")
async def reset_session(db: DatabaseClient = Depends(get_db)):
    """Resets all assessment findings and tasks to return to standby."""
    await db.clear_all()
    return {"status": "success", "message": "Session reset successfully. Engine returned to standby."}

@router.get("/debug")
async def get_debug_state(db: DatabaseClient = Depends(get_db)):
    """Inspects the raw internal database state to see where tasks are stuck."""
    return {
        "assets_count": len(db.assets),
        "vulnerabilities_count": len(db.vulnerabilities),
        "tasks_count": len(db.tasks),
        "all_tasks": list(db.tasks.values()),
        "all_vulnerabilities": list(db.vulnerabilities.values())
    }
