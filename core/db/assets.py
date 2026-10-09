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

class AssetDBMixin:
    async def insert_asset(self, asset: TargetAsset) -> str:
        async with self._lock:
            self.assets[asset.id] = asset

        if self.use_postgres and self.pg_pool:
            try:
                async with self.pg_pool.acquire() as conn:
                    await conn.execute("""
                        INSERT INTO assets (id, target, asset_type, host, port, protocol, is_authorized, metadata, status)
                        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
                        ON CONFLICT (id) DO UPDATE SET
                            target = EXCLUDED.target,
                            asset_type = EXCLUDED.asset_type,
                            is_authorized = EXCLUDED.is_authorized,
                            metadata = EXCLUDED.metadata,
                            status = EXCLUDED.status;
                    """, 
                        asset.id, 
                        asset.asset_identifier, 
                        asset.layer, 
                        asset.metadata.get("host", asset.asset_identifier),
                        asset.metadata.get("port"),
                        asset.metadata.get("protocol", "tcp"),
                        asset.is_authorized,
                        json.dumps(asset.metadata),
                        "pending"
                    )
            except Exception as e:
                logger.warning(f"PostgreSQL insert_asset error: {e}")

        return asset.id

    async def get_asset(self, asset_id: str) -> Optional[TargetAsset]:
        async with self._lock:
            return self.assets.get(asset_id)

    async def get_all_assets(self) -> List[TargetAsset]:
        async with self._lock:
            return list(self.assets.values())

    # --- Vulnerability Operations ---

