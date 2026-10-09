import asyncio
import json
import logging
import os
import uuid
from typing import Optional, List, Dict, Any
from datetime import datetime, timezone

from core.models import (
    TargetAsset, VulnerabilityRecord, TaskItem, 
    RemediationPlan, AttackPath, VulnStatus
)

logger = logging.getLogger("SharedDatabase")

class SnapshotDBMixin:
    async def get_snapshot(self) -> Dict[str, Any]:
        """Provides a complete serializable snapshot of the security assessment."""
        async with self._lock:
            return {
                "scan_session": dict(self.scan_session),
                "assets": [a.model_dump() if hasattr(a, "model_dump") else a.dict() for a in self.assets.values()],
                "vulnerabilities": [v.model_dump() if hasattr(v, "model_dump") else v.dict() for v in self.vulnerabilities.values()],
                "tasks": [t.model_dump() if hasattr(t, "model_dump") else t.dict() for t in self.tasks.values()],
                "attack_paths": [p.model_dump() if hasattr(p, "model_dump") else p.dict() for p in self.attack_paths.values()],
                "remediations": [r.model_dump() if hasattr(r, "model_dump") else r.dict() for r in self.remediations.values()],
                "retests": list(self.retests.values())
            }