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

class RemediationDBMixin:
    async def insert_remediation_plan(self, plan: RemediationPlan) -> str:
        async with self._lock:
            self.remediations[plan.id] = plan

        if self.use_postgres and self.pg_pool:
            try:
                async with self.pg_pool.acquire() as conn:
                    await conn.execute("""
                        INSERT INTO remediations (
                            id, finding_id, root_cause, fix_suggestion, 
                            code_snippet, target_tech_stack, original_code_snippet, 
                            patch_type, priority, applied, status
                        )
                        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
                        ON CONFLICT (id) DO UPDATE SET
                            root_cause = EXCLUDED.root_cause,
                            fix_suggestion = EXCLUDED.fix_suggestion,
                            code_snippet = EXCLUDED.code_snippet,
                            applied = EXCLUDED.applied,
                            status = EXCLUDED.status;
                    """,
                        plan.id,
                        plan.vulnerability_id,
                        plan.root_cause_analysis,
                        f"Apply patch for {plan.vulnerability_id}",
                        plan.patched_code_snippet,
                        plan.target_tech_stack,
                        plan.original_code_snippet,
                        plan.patch_type,
                        50,
                        plan.is_applied,
                        "pending"
                    )
            except Exception as e:
                logger.warning(f"PostgreSQL insert_remediation_plan error: {e}")

        return plan.id

    # --- Retest Operations ---

    async def record_retest(
        self, 
        finding_id: str, 
        remediation_id: Optional[str] = None, 
        still_vulnerable: bool = False, 
        evidence: str = ""
    ) -> str:
        """Records a patch verification / retest audit event in DB."""
        retest_id = str(uuid.uuid4())
        record = {
            "id": retest_id,
            "finding_id": finding_id,
            "remediation_id": remediation_id,
            "still_vulnerable": still_vulnerable,
            "evidence": evidence,
            "retested_at": datetime.now(timezone.utc).isoformat(),
            "status": "done"
        }
        async with self._lock:
            self.retests[retest_id] = record

        if self.use_postgres and self.pg_pool:
            try:
                async with self.pg_pool.acquire() as conn:
                    await conn.execute("""
                        INSERT INTO retests (id, finding_id, remediation_id, still_vulnerable, evidence, status)
                        VALUES ($1, $2, $3, $4, $5, 'done');
                    """,
                        retest_id,
                        finding_id,
                        remediation_id,
                        still_vulnerable,
                        evidence
                    )
            except Exception as e:
                logger.warning(f"PostgreSQL record_retest error: {e}")

        return retest_id

    async def get_retests(self, finding_id: Optional[str] = None) -> List[Dict[str, Any]]:
        async with self._lock:
            records = list(self.retests.values())
            if finding_id:
                return [r for r in records if r.get("finding_id") == finding_id]
            return records

