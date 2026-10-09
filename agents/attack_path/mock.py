import asyncio
import logging
from typing import Dict, Any, List, Optional, Tuple
import networkx as nx
from core.models import VulnerabilityRecord, TargetAsset, TaskItem
class MockAttackPathLLM:
    """Deterministic capability-based fallback for evaluating vulnerability chaining."""
    
    async def evaluate_chainability(self, vuln: VulnerabilityRecord, all_assets: List[TargetAsset]) -> Tuple[str, str, bool]:
        if vuln.has_leaked_creds or "metadata" in vuln.title.lower() or "ssrf" in vuln.title.lower():
            public_asset = next((a for a in all_assets if a.id == vuln.asset_id or (a.layer in ["Web", "Network"] and not a.metadata.get("is_crown_jewel"))), None)
            crown_jewel = next((a for a in all_assets if a.metadata.get("is_crown_jewel")), None)
            if public_asset and crown_jewel:
                return public_asset.id, crown_jewel.id, True

        if vuln.layer in ["Network", "Web", "OSINT"]:
            return "INTERNET", vuln.asset_id, True
                
        return "", "", False

    async def evaluate_vuln_transition(self, parent_vuln: VulnerabilityRecord, child_vuln: VulnerabilityRecord) -> Dict[str, Any]:
        """Evaluates causal transition from parent to child vulnerability."""
        if parent_vuln.has_leaked_creds:
            return {
                "is_chainable": True,
                "transition_probability": 0.88,
                "chain_mechanism": "Credential Reuse & Authenticated Session Pivot",
                "exploitation_path": f"Adversary replays credentials harvested from '{parent_vuln.title}' to authenticate against '{child_vuln.title}'.",
                "causal_reason": f"Compromised credentials from '{parent_vuln.title}' satisfy authentication barriers required to trigger '{child_vuln.title}'."
            }
        if any(w in parent_vuln.title.lower() for w in ["ssrf", "rce", "command", "proxy", "metadata"]):
            return {
                "is_chainable": True,
                "transition_probability": 0.85,
                "chain_mechanism": "Internal Network Shell Tunneling",
                "exploitation_path": f"Adversary uses command execution shell on '{parent_vuln.title}' to pivot internal socket requests into '{child_vuln.title}'.",
                "causal_reason": f"Internal network pivot established via '{parent_vuln.title}' bypasses firewalls to expose '{child_vuln.title}'."
            }
        if any(w in parent_vuln.title.lower() for w in ["lfi", "traversal", "23017", "file", "env", "git", "secret"]):
            return {
                "is_chainable": True,
                "transition_probability": 0.80,
                "chain_mechanism": "Secret Token & Configuration Extraction",
                "exploitation_path": f"Sensitive database configuration strings leaked by '{parent_vuln.title}' are passed into '{child_vuln.title}'.",
                "causal_reason": f"Local file disclosure via '{parent_vuln.title}' leaks tokens and secrets required to target '{child_vuln.title}'."
            }
        return {
            "is_chainable": False,
            "transition_probability": 0.0,
            "chain_mechanism": "No direct causal link",
            "exploitation_path": "",
            "causal_reason": "No causal link."
        }

MockAttackPathCorrelator = MockAttackPathLLM


