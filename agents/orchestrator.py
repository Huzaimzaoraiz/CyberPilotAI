import asyncio
import logging
from typing import Dict, Any
from core.models import AgentType, TaskItem
from agents.vapt import VAPTAgent, MockLLMClient
from agents.validation import ValidationAgent, MockValidationLLM
from agents.attack_path.agent import AttackPathAgent
from agents.attack_path.mock import MockAttackPathLLM
from agents.threat_intel import ThreatIntelAgent
from agents.remediation import RemediationAgent, MockRemediationLLM
from agents.retesting import RetestingAgent, MockRetestEvaluator
from tools.llm import RealLLMClient
from core.config import settings

logger = logging.getLogger("Orchestrator")

class Orchestrator:
    def __init__(self, db_client):
        self.db = db_client
        # Map agent enums to their respective async handlers.
        # As we build the real agents in the next steps, we will replace 
        # these mock functions with actual Agent class initializations.
        if settings.has_llm:
            self.llm_client = RealLLMClient(api_key=settings.LLM_API_KEY, base_url=settings.LLM_BASE_URL, model=settings.LLM_MODEL)
        else:
            self.llm_client = MockLLMClient()
            
        self.vapt_agent = VAPTAgent(db_client=db_client, llm_client=self.llm_client, nvd_api_key=settings.NVD_API_KEY)
        self.validation_agent = ValidationAgent(db_client, self.llm_client)
        self.attack_path_agent = AttackPathAgent(db_client, self.llm_client)
        self.threat_intel_agent = ThreatIntelAgent(db_client, config={
            "vt_api_key": settings.VT_API_KEY,
            "hibp_api_key": settings.HIBP_API_KEY
        })
        self.remediation_agent = RemediationAgent(db_client, self.llm_client)
        self.retest_agent = RetestingAgent(db_client, MockRetestEvaluator())
        
        self.agent_routers = {
            AgentType.VAPT: self.vapt_agent.execute_task,
            AgentType.VALIDATION: self.validation_agent.execute_task,
            AgentType.ATTACK_PATH: self.attack_path_agent.execute_task,
            AgentType.THREAT_INTEL: self.threat_intel_agent.execute_task,
            AgentType.REMEDIATION: self.remediation_agent.execute_task,
            AgentType.RETEST: self.retest_agent.execute_task,
        }

    async def run_main_loop(self):
        """The continuous central loop of the AI system."""
        logger.info("Starting Orchestrator Main Loop...")
        try:
            while True:
                # 1. Fetch the highest priority pending task
                task = await self.db.get_highest_priority_task()
                
                if not task:
                    # Queue is empty, sleep briefly before polling again
                    await asyncio.sleep(2)
                    continue

                logger.info(f"Picked up [Priority {task.priority}] Task for {task.target_agent.value} (Task ID: {task.id[:8]})")
                
                # 2. Mark as in-progress to prevent other loop iterations from grabbing it
                await self.db.mark_task_in_progress(task.id)

                # 3. Route to the correct agent
                handler = self.agent_routers.get(task.target_agent)
                
                if handler:
                    # Spawn the agent non-blockingly using asyncio.create_task.
                    # This allows the Orchestrator to instantly fetch the next task in the queue.
                    asyncio.create_task(self._execute_agent(handler, task))
                else:
                    logger.error(f"Unknown agent type requested: {task.target_agent}")
                    await self.db.complete_task(task.id, status="failed")
                    
                await asyncio.sleep(0.5) # Slight delay to keep terminal output readable in this demo
                
        except asyncio.CancelledError:
            logger.info("Orchestrator shutting down cleanly...")

    async def _execute_agent(self, handler_func, task: TaskItem):
        """Wrapper to execute agent logic, catch errors, and handle task cleanup."""
        try:
            await handler_func(task.payload)
            await self.db.complete_task(task.id, status="completed")
            logger.info(f"Task {task.id[:8]} completed successfully.")
        except Exception as e:
            logger.error(f"Agent failed on task {task.id[:8]}: {str(e)}")
            await self.db.complete_task(task.id, status="failed")

    # --- Mock Agent Handlers ---
    # These simulate the time it takes for agents to do their jobs.
    
    async def _mock_vapt_agent(self, payload: Dict[str, Any]):
        logger.info(f"-> [VAPT Agent] Running discovery on asset: {payload.get('asset_id')}")
        await asyncio.sleep(2) # Simulating nmap / recon

    async def _mock_validation_agent(self, payload: Dict[str, Any]):
        logger.info(f"-> [Validation Agent] Generating PoC for vuln: {payload.get('vulnerability_id')}")
        await asyncio.sleep(1.5)

    async def _mock_attack_path_agent(self, payload: Dict[str, Any]):
        logger.info(f"-> [Attack-Path Agent] Recalculating graph...")
        await asyncio.sleep(0.5)

    async def _mock_threat_intel_agent(self, payload: Dict[str, Any]):
        logger.info(f"-> [Threat Intel Agent] Checking HIBP/VirusTotal for asset: {payload.get('asset_id')}")
        await asyncio.sleep(1)

    async def _mock_remediation_agent(self, payload: Dict[str, Any]):
        logger.info(f"-> [Remediation Agent] Writing code patch for vuln: {payload.get('vulnerability_id')}")
        await asyncio.sleep(2)

    async def _mock_retest_agent(self, payload: Dict[str, Any]):
        logger.info(f"-> [Retest Agent] Verifying staging environment patch...")
        await asyncio.sleep(1)