# main.py
import asyncio
import logging
from contextlib import asynccontextmanager
from fastapi import FastAPI
import uvicorn

from core.database import DatabaseClient
from core.models import TargetAsset, TaskItem, AgentType
from agents.orchestrator import Orchestrator
from api.routes import router as api_router

# Configure explicit console logging
logging.basicConfig(
    level=logging.INFO, 
    format='%(asctime)s | %(levelname)-7s | %(name)s | %(message)s', 
    datefmt='%H:%M:%S'
)
logger = logging.getLogger("Main")

async def safe_orchestrator_runner(orchestrator: Orchestrator):
    """Wrapper that catches and prints ANY background task crash directly to console."""
    try:
        await orchestrator.run_main_loop()
    except Exception as e:
        logger.critical(f"ORCHESTRATOR CRASHED: {e}", exc_info=True)

@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Initializing Shared Database (Standby mode - awaiting target)...")
    db = DatabaseClient()
    app.state.db = db
    
    # Standby: No targets or tasks are seeded. Engine will wait until a target is submitted.
    
    logger.info("Starting Orchestrator Background Task...")
    try:
        orchestrator = Orchestrator(db_client=db)
        app.state.orchestrator = orchestrator
        app.state.orchestrator_task = asyncio.create_task(safe_orchestrator_runner(orchestrator))
    except Exception as e:
        logger.critical(f"Failed to initialize Orchestrator: {e}", exc_info=True)
    
    yield
    
    logger.info("Shutting down Orchestrator...")
    if hasattr(app.state, "orchestrator_task"):
        app.state.orchestrator_task.cancel()
        try:
            await app.state.orchestrator_task
        except asyncio.CancelledError:
            logger.info("Orchestrator successfully terminated.")

from fastapi.responses import FileResponse, HTMLResponse
import os

app = FastAPI(
    title="AI Pentest Engine API",
    description="Backend API for autonomous multi-agent security platform.",
    lifespan=lifespan
)

app.include_router(api_router)

@app.get("/", response_class=HTMLResponse)
@app.get("/dashboard", response_class=HTMLResponse)
async def serve_dashboard():
    """Serves the visual cyber-operations dashboard."""
    index_path = os.path.join(os.path.dirname(__file__), "web", "index.html")
    return FileResponse(index_path)

if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)