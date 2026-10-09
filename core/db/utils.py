from typing import Any
def normalize_source(raw_source: str) -> str:
    """Strictly enforces source IN ('tool', 'ai_inference') per DB schema constraints."""
    s = (raw_source or "").lower()
    if any(k in s for k in ("tool", "nmap", "intel", "mcp", "scanner", "cve", "recon")):
        return "tool"
    return "ai_inference"


def normalize_status(raw_status: Any) -> str:
    """Maps domain status to relational lifecycle status ('pending', 'processing', 'done')."""
    val = raw_status.value if hasattr(raw_status, "value") else str(raw_status)
    s = val.lower().strip()
    if s in ("unvalidated", "pending"):
        return "pending"
    elif s in ("validating", "processing", "in_progress"):
        return "processing"
    elif s in ("validated", "remediated", "false_positive", "done", "completed"):
        return "done"
    return "pending"



