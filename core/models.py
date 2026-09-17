from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any
from enum import Enum
from datetime import datetime, timezone
import uuid

def generate_uuid() -> str:
    return str(uuid.uuid4())

# --- Enums for Strict State Management ---
class VulnStatus(str, Enum):
    UNVALIDATED = "unvalidated"
    VALIDATING = "validating"
    VALIDATED = "validated"
    FALSE_POSITIVE = "false_positive"
    REMEDIATED = "remediated"

class AgentType(str, Enum):
    VAPT = "vapt_agent"
    VALIDATION = "validation_agent"
    ATTACK_PATH = "attack_path_agent"
    THREAT_INTEL = "threat_intel_agent"
    REMEDIATION = "remediation_agent"
    RETEST = "retest_agent"

# --- Core Database Models ---

class TargetAsset(BaseModel):
    """Strictly defines authorized targets. Agents must check this before acting."""
    id: str = Field(default_factory=generate_uuid)
    asset_identifier: str  # e.g., "api.example.com" or "192.168.1.0/24"
    layer: str             # 'Network', 'Web', 'Cloud', 'Host'
    is_authorized: bool = True 
    metadata: Dict[str, Any] = Field(default_factory=dict)

class VulnerabilityRecord(BaseModel):
    """Tracks a finding's lifecycle. Explicitly separates tool evidence from AI inference."""
    id: str = Field(default_factory=generate_uuid)
    asset_id: str
    title: str
    criticality_score: float = Field(..., ge=0.0, le=10.0) 
    layer: str
    status: VulnStatus = VulnStatus.UNVALIDATED
    discovery_source: str  # e.g., 'TOOL_NMAP', 'AI_INFERENCE', 'THREAT_INTEL'
    confidence_score: float = Field(default=0.5, ge=0.0, le=1.0)
    has_leaked_creds: bool = False  # SECURITY CONSTRAINT: Boolean only, NEVER the raw string
    attack_path_id: Optional[str] = None
    proof_of_concept: Optional[str] = None  # The benign payload used for validation
    metadata: Dict[str, Any] = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

class TaskItem(BaseModel):
    """A job in the Orchestrator's Priority Queue."""
    id: str = Field(default_factory=generate_uuid)
    target_agent: AgentType
    priority: int = Field(..., description="Higher integer = processed first")
    payload: Dict[str, Any]  # Data required by the agent (e.g., vuln_id)
    status: str = "pending"  # 'pending', 'in_progress', 'completed', 'failed'
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

class RemediationPlan(BaseModel):
    """AI-generated fix instructions bound to a specific vulnerability."""
    id: str = Field(default_factory=generate_uuid)
    vulnerability_id: str
    root_cause_analysis: str
    target_tech_stack: str
    original_code_snippet: Optional[str] = None
    patched_code_snippet: str
    patch_type: str          # 'code', 'configuration', 'iac'
    source: str = "AI_INFERENCE" 
    is_applied: bool = False
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

class AttackPath(BaseModel):
    """A graphed chain of vulnerabilities leading to a crown jewel."""
    id: str = Field(default_factory=generate_uuid)
    nodes: List[str]         # List of Asset IDs
    edges: List[str]         # List of Vulnerability IDs connecting the nodes
    total_risk_score: float
    chokepoint_vuln_id: str  # The critical vulnerability to patch to break the chain
    path_probability: float = 1.0  # Cumulative probability of successful chain exploitation (0.0 to 1.0)
    step_details: List[Dict[str, Any]] = Field(default_factory=list)  # Step-by-step causal tracing
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))