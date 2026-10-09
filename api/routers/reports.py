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

from report.json_export import generate_json_report
from report.pdf_export import generate_pdf_report
from fastapi.responses import Response

router = APIRouter()

@router.get("/report/json")
async def export_report_json(db: DatabaseClient = Depends(get_db)):
    """Downloads structured assessment summary as JSON."""
    snapshot = await db.get_snapshot() if hasattr(db, "get_snapshot") else {
        "scan_session": getattr(db, "scan_session", {}),
        "assets": [a.model_dump() if hasattr(a, "model_dump") else a.dict() for a in db.assets.values()],
        "vulnerabilities": [v.model_dump() if hasattr(v, "model_dump") else v.dict() for v in db.vulnerabilities.values()],
        "attack_paths": [p.model_dump() if hasattr(p, "model_dump") else p.dict() for p in db.attack_paths.values()],
        "remediations": [r.model_dump() if hasattr(r, "model_dump") else r.dict() for r in db.remediations.values()],
        "retests": getattr(db, "retests", {})
    }
    return generate_json_report(snapshot)

@router.get("/report/pdf")
async def export_report_pdf(db: DatabaseClient = Depends(get_db)):
    """Downloads formatted, publication-grade executive and technical PDF report."""
    snapshot = await db.get_snapshot() if hasattr(db, "get_snapshot") else {
        "scan_session": getattr(db, "scan_session", {}),
        "assets": [a.model_dump() if hasattr(a, "model_dump") else a.dict() for a in db.assets.values()],
        "vulnerabilities": [v.model_dump() if hasattr(v, "model_dump") else v.dict() for v in db.vulnerabilities.values()],
        "attack_paths": [p.model_dump() if hasattr(p, "model_dump") else p.dict() for p in db.attack_paths.values()],
        "remediations": [r.model_dump() if hasattr(r, "model_dump") else r.dict() for r in db.remediations.values()],
        "retests": getattr(db, "retests", {})
    }
    pdf_bytes = generate_pdf_report(snapshot)
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={
            "Content-Disposition": 'attachment; filename="Security_Assessment_Report.pdf"'
        }
    )