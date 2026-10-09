from pydantic import BaseModel
from typing import Optional, List

class PoCSchema(BaseModel):
    payload: str
    expected_marker: str

class ChainabilitySchema(BaseModel):
    source_node_id: str
    target_node_id: str
    is_chainable: bool

class RemediationSchema(BaseModel):
    root_cause_analysis: str
    target_tech_stack: str
    original_code_snippet: str
    patched_code_snippet: str
    patch_type: str


