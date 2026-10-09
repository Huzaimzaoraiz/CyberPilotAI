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

from .utils import normalize_source, normalize_status

class VulnerabilityDBMixin:
    async def insert_vulnerability(self, vuln: VulnerabilityRecord) -> str:
        async with self._lock:
            self.vulnerabilities[vuln.id] = vuln

        if self.use_postgres and self.pg_pool:
            try:
                clean_source = normalize_source(vuln.discovery_source)
                clean_status = normalize_status(vuln.status)
                async with self.pg_pool.acquire() as conn:
                    await conn.execute("""
                        INSERT INTO findings (
                            id, asset_id, title, description, severity, cve_id, 
                            source, raw_evidence, criticality_score, confidence_score, 
                            has_leaked_creds, layer, metadata, status
                        )
                        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
                        ON CONFLICT (id) DO UPDATE SET
                            title = EXCLUDED.title,
                            criticality_score = EXCLUDED.criticality_score,
                            confidence_score = EXCLUDED.confidence_score,
                            has_leaked_creds = EXCLUDED.has_leaked_creds,
                            metadata = EXCLUDED.metadata,
                            status = EXCLUDED.status;
                    """,
                        vuln.id,
                        vuln.asset_id,
                        vuln.title,
                        vuln.metadata.get("description", vuln.title),
                        vuln.metadata.get("severity", "MEDIUM"),
                        vuln.metadata.get("cve_id"),
                        clean_source,
                        vuln.proof_of_concept or vuln.metadata.get("evidence", ""),
                        float(vuln.criticality_score),
                        float(vuln.confidence_score),
                        bool(vuln.has_leaked_creds),
                        vuln.layer,
                        json.dumps(vuln.metadata),
                        clean_status
                    )
            except Exception as e:
                logger.warning(f"PostgreSQL insert_vulnerability error: {e}")

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
                for key, value in kwargs.items():
                    if hasattr(vuln, key):
                        setattr(vuln, key, value)

        if self.use_postgres and self.pg_pool:
            try:
                vuln = self.vulnerabilities.get(vuln_id)
                if vuln:
                    clean_status = normalize_status(vuln.status)
                    async with self.pg_pool.acquire() as conn:
                        await conn.execute("""
                            UPDATE findings SET
                                criticality_score = $2,
                                confidence_score = $3,
                                raw_evidence = $4,
                                status = $5,
                                metadata = $6
                            WHERE id = $1;
                        """,
                            vuln.id,
                            float(vuln.criticality_score),
                            float(vuln.confidence_score),
                            vuln.proof_of_concept or "",
                            clean_status,
                            json.dumps(vuln.metadata)
                        )

                        # If validated, record in validated_findings
                        if vuln.status == VulnStatus.VALIDATED:
                            val_id = f"val_{vuln.id}"
                            await conn.execute("""
                                INSERT INTO validated_findings (
                                    id, finding_id, exploitable, confidence_score, 
                                    cvss_score, poc_exists, validation_evidence, mitre_technique, status
                                )
                                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
                                ON CONFLICT (id) DO UPDATE SET
                                    exploitable = EXCLUDED.exploitable,
                                    confidence_score = EXCLUDED.confidence_score,
                                    poc_exists = EXCLUDED.poc_exists,
                                    validation_evidence = EXCLUDED.validation_evidence,
                                    status = EXCLUDED.status;
                            """,
                                val_id,
                                vuln.id,
                                True,
                                float(vuln.confidence_score),
                                float(vuln.criticality_score),
                                bool(vuln.proof_of_concept),
                                vuln.proof_of_concept or "Validated non-destructively",
                                vuln.metadata.get("mitre_technique", "T1190"),
                                "done"
                            )
            except Exception as e:
                logger.warning(f"PostgreSQL update_vulnerability error: {e}")

    async def boost_vulnerability_priority(self, vuln_id: str, multiplier: float):
        """Used by the Attack-Path agent to increase priority based on contextual risk."""
        async with self._lock:
            if vuln_id in self.vulnerabilities:
                vuln = self.vulnerabilities[vuln_id]
                new_score = min(10.0, vuln.criticality_score * multiplier)
                vuln.criticality_score = new_score
                logger.info(f"Boosted Vuln {vuln_id} score to {new_score}")
        
        await self.update_vulnerability(vuln_id, criticality_score=new_score)

    # --- Task Queue (Orchestrator) Operations ---

