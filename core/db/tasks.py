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

from .utils import normalize_status

class TaskDBMixin:
    async def insert_task(self, task: TaskItem) -> str:
        async with self._lock:
            self.tasks[task.id] = task

        if self.use_postgres and self.pg_pool:
            try:
                async with self.pg_pool.acquire() as conn:
                    await conn.execute("""
                        INSERT INTO tasks (id, target_agent, priority, payload, status)
                        VALUES ($1, $2, $3, $4, $5)
                        ON CONFLICT (id) DO UPDATE SET
                            priority = EXCLUDED.priority,
                            payload = EXCLUDED.payload,
                            status = EXCLUDED.status;
                    """,
                        task.id,
                        str(task.target_agent),
                        int(task.priority),
                        json.dumps(task.payload),
                        str(task.status)
                    )
            except Exception as e:
                logger.warning(f"PostgreSQL insert_task error: {e}")

        return task.id

    async def get_highest_priority_task(self) -> Optional[TaskItem]:
        """Fetches the pending task with the highest priority integer."""
        async with self._lock:
            pending_tasks = [t for t in self.tasks.values() if t.status == "pending"]
            if not pending_tasks:
                return None
            pending_tasks.sort(key=lambda x: x.priority, reverse=True)
            return pending_tasks[0]

    async def mark_task_in_progress(self, task_id: str):
        async with self._lock:
            if task_id in self.tasks:
                self.tasks[task_id].status = "in_progress"

        if self.use_postgres and self.pg_pool:
            try:
                async with self.pg_pool.acquire() as conn:
                    await conn.execute("UPDATE tasks SET status = 'in_progress' WHERE id = $1;", task_id)
            except Exception as e:
                logger.warning(f"PostgreSQL mark_task_in_progress error: {e}")

    async def complete_task(self, task_id: str, status: str = "completed"):
        async with self._lock:
            if task_id in self.tasks:
                self.tasks[task_id].status = status

        if self.use_postgres and self.pg_pool:
            try:
                async with self.pg_pool.acquire() as conn:
                    await conn.execute("UPDATE tasks SET status = $2 WHERE id = $1;", task_id, status)
            except Exception as e:
                logger.warning(f"PostgreSQL complete_task error: {e}")

    # --- Attack Path & Remediation Operations ---

