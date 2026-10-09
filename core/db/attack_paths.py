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

class AttackPathDBMixin:
    async def save_attack_path(self, path: AttackPath) -> str:
        async with self._lock:
            self.attack_paths[path.id] = path

        if self.use_postgres and self.pg_pool:
            try:
                async with self.pg_pool.acquire() as conn:
                    await conn.execute("""
                        INSERT INTO attack_paths (
                            id, path_nodes, path_edges, cumulative_risk, 
                            break_chain_target, mitre_chain, attack_narrative, 
                            simplified_flow, grouped_vectors, status
                        )
                        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
                        ON CONFLICT (id) DO UPDATE SET
                            path_nodes = EXCLUDED.path_nodes,
                            path_edges = EXCLUDED.path_edges,
                            cumulative_risk = EXCLUDED.cumulative_risk,
                            break_chain_target = EXCLUDED.break_chain_target,
                            mitre_chain = EXCLUDED.mitre_chain,
                            attack_narrative = EXCLUDED.attack_narrative,
                            simplified_flow = EXCLUDED.simplified_flow,
                            grouped_vectors = EXCLUDED.grouped_vectors,
                            status = EXCLUDED.status;
                    """,
                        path.id,
                        json.dumps(path.nodes),
                        json.dumps(path.edges),
                        float(path.total_risk_score),
                        path.chokepoint_vuln_id,
                        json.dumps(path.mitre_tactics),
                        path.attack_narrative,
                        json.dumps(path.simplified_flow),
                        json.dumps(path.grouped_vectors),
                        "done"
                    )
            except Exception as e:
                logger.warning(f"PostgreSQL save_attack_path error: {e}")

        return path.id

    async def clear_attack_paths(self):
        async with self._lock:
            self.attack_paths.clear()

        if self.use_postgres and self.pg_pool:
            try:
                async with self.pg_pool.acquire() as conn:
                    await conn.execute("TRUNCATE TABLE attack_paths CASCADE;")
            except Exception as e:
                logger.warning(f"PostgreSQL clear_attack_paths error: {e}")

