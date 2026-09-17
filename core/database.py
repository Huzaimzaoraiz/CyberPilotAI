import asyncio
import logging
from typing import Optional, List, Dict
from core.models import (
    TargetAsset, VulnerabilityRecord, TaskItem, 
    RemediationPlan, AttackPath, VulnStatus
)

logger = logging.getLogger("SharedDatabase")

class DatabaseClient:
    """
    An asynchronous, thread-safe in-memory database.
    Provides the required interface for all Agents and the Orchestrator.
    """
    def __init__(self):
        self._lock = asyncio.Lock()
        
        # In-memory tables
        self.assets: Dict[str, TargetAsset] = {}
        self.vulnerabilities: Dict[str, VulnerabilityRecord] = {}
        self.tasks: Dict[str, TaskItem] = {}
        self.remediations: Dict[str, RemediationPlan] = {}
        self.attack_paths: Dict[str, AttackPath] = {}
        self.scan_session: Dict = {
            "is_active": False,
            "started_at": None,
            "completed_at": None,
            "target": None
        }

    async def clear_all(self):
        """Clears all session data to allow running a fresh scan."""
        async with self._lock:
            self.assets.clear()
            self.vulnerabilities.clear()
            self.tasks.clear()
            self.remediations.clear()
            self.attack_paths.clear()
            self.scan_session = {
                "is_active": False,
                "started_at": None,
                "completed_at": None,
                "target": None
            }

    # --- Asset Operations ---
    
    async def insert_asset(self, asset: TargetAsset) -> str:
        async with self._lock:
            self.assets[asset.id] = asset
        return asset.id

    async def get_asset(self, asset_id: str) -> Optional[TargetAsset]:
        async with self._lock:
            return self.assets.get(asset_id)

    async def get_all_assets(self) -> List[TargetAsset]:
        async with self._lock:
            return list(self.assets.values())

    # --- Vulnerability Operations ---

    async def insert_vulnerability(self, vuln: VulnerabilityRecord) -> str:
        async with self._lock:
            self.vulnerabilities[vuln.id] = vuln
        return vuln.id

    async def get_vulnerability(self, vuln_id: str) -> Optional[VulnerabilityRecord]:
        async with self._lock:
            return self.vulnerabilities.get(vuln_id)

    async def get_vulnerabilities(self, status: Optional[VulnStatus] = None) -> List[VulnerabilityRecord]:
        async with self._lock:
            if status:
                return [v for v in self.vulnerabilities.values() if v.status == status]
            return list(self.vulnerabilities.values())

    async def update_vulnerability(self, vuln_id: str, **kwargs):
        async with self._lock:
            if vuln_id in self.vulnerabilities:
                vuln = self.vulnerabilities[vuln_id]
                # Update attributes dynamically
                for key, value in kwargs.items():
                    if hasattr(vuln, key):
                        setattr(vuln, key, value)

    async def boost_vulnerability_priority(self, vuln_id: str, multiplier: float):
        """Used by the Attack-Path agent to increase priority based on contextual risk."""
        async with self._lock:
            if vuln_id in self.vulnerabilities:
                vuln = self.vulnerabilities[vuln_id]
                new_score = min(10.0, vuln.criticality_score * multiplier)
                vuln.criticality_score = new_score
                logger.info(f"Boosted Vuln {vuln_id} score to {new_score}")

    # --- Task Queue (Orchestrator) Operations ---

    async def insert_task(self, task: TaskItem) -> str:
        async with self._lock:
            self.tasks[task.id] = task
        return task.id

    async def get_highest_priority_task(self) -> Optional[TaskItem]:
        """Fetches the pending task with the highest priority integer."""
        async with self._lock:
            pending_tasks = [t for t in self.tasks.values() if t.status == "pending"]
            if not pending_tasks:
                return None
            # Sort by priority descending, then return the highest
            pending_tasks.sort(key=lambda x: x.priority, reverse=True)
            return pending_tasks[0]

    async def mark_task_in_progress(self, task_id: str):
        async with self._lock:
            if task_id in self.tasks:
                self.tasks[task_id].status = "in_progress"

    async def complete_task(self, task_id: str, status: str = "completed"):
        async with self._lock:
            if task_id in self.tasks:
                self.tasks[task_id].status = status

    # --- Attack Path & Remediation Operations ---

    async def save_attack_path(self, path: AttackPath) -> str:
        async with self._lock:
            self.attack_paths[path.id] = path
        return path.id

    async def insert_remediation_plan(self, plan: RemediationPlan) -> str:
        async with self._lock:
            self.remediations[plan.id] = plan
        return plan.id