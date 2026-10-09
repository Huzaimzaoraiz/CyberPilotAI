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

class ModelSwitchRequest(BaseModel):
    model: str

@router.get("/models")
async def get_models_status(request: Request):
    """Returns active model, available fallback chain, and quota state."""
    orchestrator = getattr(request.app.state, "orchestrator", None)
    if orchestrator and hasattr(orchestrator, "llm_client") and hasattr(orchestrator.llm_client, "get_model_status"):
        return orchestrator.llm_client.get_model_status()
    from core.config import settings
    return {
        "current_model": settings.LLM_MODEL,
        "fallback_models": settings.LLM_FALLBACK_MODELS,
        "is_quota_exhausted": False
    }

@router.post("/models/switch")
async def switch_active_model(req: ModelSwitchRequest, request: Request):
    """Dynamically switches active model mid-session without restarting."""
    from core.config import settings
    orchestrator = getattr(request.app.state, "orchestrator", None)
    settings.LLM_MODEL = req.model
    if orchestrator and hasattr(orchestrator, "llm_client") and hasattr(orchestrator.llm_client, "switch_model"):
        orchestrator.llm_client.switch_model(req.model)
    return {
        "message": f"Successfully switched active model to {req.model}",
        "active_model": req.model
    }

# --- 8. On-Demand Vulnerability Scanners (SAST & Web) ---

