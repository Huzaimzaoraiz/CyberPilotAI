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

class DatabaseConnection:
    def __init__(self, database_url: Optional[str] = None):
        self._lock = asyncio.Lock()
        self.database_url = database_url or os.getenv("DATABASE_URL")
        self.pg_pool = None
        self.use_postgres = False
        
        # In-memory tables (always maintained for zero-latency queries & fallback)
        self.assets: Dict[str, TargetAsset] = {}
        self.vulnerabilities: Dict[str, VulnerabilityRecord] = {}
        self.tasks: Dict[str, TaskItem] = {}
        self.remediations: Dict[str, RemediationPlan] = {}
        self.attack_paths: Dict[str, AttackPath] = {}
        self.retests: Dict[str, Dict[str, Any]] = {}
        self.scan_session: Dict[str, Any] = {
            "is_active": False,
            "started_at": None,
            "completed_at": None,
            "target": None
        }

    async def initialize(self):
        """Initializes PostgreSQL connection pool if configured, with schema verification."""
        if not self.database_url:
            logger.info("DATABASE_URL not set; running in thread-safe in-memory database mode.")
            return

        try:
            import asyncpg
            logger.info(f"Connecting to PostgreSQL persistence layer...")
            self.pg_pool = await asyncpg.create_pool(
                dsn=self.database_url,
                min_size=1,
                max_size=10,
                timeout=5.0,
                command_timeout=10.0
            )
            
            # Apply schema if schema file exists
            schema_candidates = [
                os.path.join(os.path.dirname(__file__), "..", "db", "schema.sql"),
                os.path.join(os.getcwd(), "db", "schema.sql")
            ]
            for schema_path in schema_candidates:
                if os.path.exists(schema_path):
                    try:
                        with open(schema_path, "r", encoding="utf-8") as f:
                            schema_sql = f.read()
                        async with self.pg_pool.acquire() as conn:
                            await conn.execute(schema_sql)
                        logger.info("PostgreSQL schema successfully verified/applied.")
                        break
                    except Exception as schema_err:
                        logger.warning(f"Could not apply schema.sql: {schema_err}")

            self.use_postgres = True
            logger.info("PostgreSQL persistence layer active.")
        except Exception as e:
            logger.warning(f"PostgreSQL connection failed ({e}). Gracefully running in in-memory mode.")
            self.pg_pool = None
            self.use_postgres = False

    async def close(self):
        """Gracefully closes the connection pool."""
        if self.pg_pool:
            try:
                await self.pg_pool.close()
            except Exception as e:
                logger.warning(f"Error closing PostgreSQL pool: {e}")
            self.pg_pool = None
            self.use_postgres = False

    async def clear_all(self):
        """Clears all session data to allow running a fresh scan."""
        async with self._lock:
            self.assets.clear()
            self.vulnerabilities.clear()
            self.tasks.clear()
            self.remediations.clear()
            self.attack_paths.clear()
            self.retests.clear()
            self.scan_session = {
                "is_active": False,
                "started_at": None,
                "completed_at": None,
                "target": None
            }

        if self.use_postgres and self.pg_pool:
            try:
                async with self.pg_pool.acquire() as conn:
                    await conn.execute("""
                        TRUNCATE TABLE retests, remediations, attack_paths, 
                                       validated_findings, findings, assets, tasks CASCADE;
                    """)
            except Exception as e:
                logger.warning(f"Failed to truncate PostgreSQL tables: {e}")

    # --- Asset Operations ---
    
