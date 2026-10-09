import os
import json
import logging
import asyncio
from typing import Dict, Any, List, Optional, Tuple
from pydantic import BaseModel
import google.generativeai as genai

logger = logging.getLogger("LLM_Engine")

from .schemas import ChainabilitySchema

class AttackPathLLMMixin:
    async def evaluate_chainability(self, vuln: Any, all_assets: List[Any]) -> Tuple[str, str, bool]:
        logger.info(f"[LLM] Evaluating if {vuln.title} enables pivoting...")
        
        asset_context = [{"id": a.id, "layer": a.layer, "crown_jewel": a.metadata.get("is_crown_jewel", False)} for a in all_assets]
        
        prompt = f"""
        Vulnerability: {vuln.title} (Layer: {vuln.layer}, Leaked Creds: {vuln.has_leaked_creds})
        Network Assets: {json.dumps(asset_context)}
        
        Does this vulnerability grant access that allows an attacker to pivot from a public asset to an internal crown jewel?
        Respond ONLY with a JSON object:
        {{"source_node_id": "<id or INTERNET>", "target_node_id": "<id>", "is_chainable": true/false}}
        """
        
        data = await self._execute_with_fallback(prompt, response_format={"type": "json_object"}, temperature=0.1)
        if data and isinstance(data, dict):
            if not data.get("is_chainable", False):
                return "INTERNET", vuln.asset_id, True
            return data.get("source_node_id", "INTERNET"), data.get("target_node_id", vuln.asset_id), True
        
        if vuln.layer in ["Network", "Web", "OSINT"]:
            if vuln.has_leaked_creds or "metadata" in vuln.title.lower():
                public_asset = next((a for a in all_assets if a.layer in ["Web", "Network"] and not a.metadata.get("is_crown_jewel")), None)
                crown_jewel = next((a for a in all_assets if a.metadata.get("is_crown_jewel")), None)
                if public_asset and crown_jewel:
                    return public_asset.id, crown_jewel.id, True
        return "", "", False

    async def evaluate_vuln_transition(self, parent_vuln: Any, child_vuln: Any) -> Dict[str, Any]:
        """
        Evaluates whether exploiting parent_vuln enables or exposes child_vuln,
        and estimates transition probability (0.0 - 1.0) and reasoning.
        """
        logger.info(f"[LLM] Evaluating causal transition: {parent_vuln.title} -> {child_vuln.title}...")
        
        prompt = f"""
        You are a cybersecurity attack path specialist.
        Parent Vulnerability: {parent_vuln.title} (Layer: {parent_vuln.layer}, Leaked Creds: {parent_vuln.has_leaked_creds}, CVSS: {parent_vuln.criticality_score})
        Child Vulnerability: {child_vuln.title} (Layer: {child_vuln.layer}, CVSS: {child_vuln.criticality_score})
        
        Can an attacker who successfully exploits the Parent Vulnerability use the gained access, privileges, or network position to expose or exploit the Child Vulnerability?
        
        Respond ONLY with a JSON object:
        {{
            "is_chainable": true/false,
            "transition_probability": <float between 0.0 and 1.0>,
            "causal_reason": "<1-2 sentence explanation of how parent enables child>"
        }}
        """
        data = await self._execute_with_fallback(prompt, response_format={"type": "json_object"}, temperature=0.1)
        if data and isinstance(data, dict):
            return {
                "is_chainable": bool(data.get("is_chainable", False)),
                "transition_probability": float(data.get("transition_probability", 0.5)),
                "causal_reason": str(data.get("causal_reason", "Causal exploit linkage established by AI inference."))
            }
        
        # Deterministic fallback
        if parent_vuln.has_leaked_creds:
            return {
                "is_chainable": True,
                "transition_probability": 0.88,
                "causal_reason": f"Compromised credentials from '{parent_vuln.title}' unlock authenticated access to exploit '{child_vuln.title}'."
            }
        if any(w in parent_vuln.title.lower() for w in ["ssrf", "rce", "command", "proxy", "metadata"]):
            return {
                "is_chainable": True,
                "transition_probability": 0.82,
                "causal_reason": f"Internal network pivot established via '{parent_vuln.title}' bypasses firewalls to reach '{child_vuln.title}'."
            }
        if any(w in parent_vuln.title.lower() for w in ["lfi", "traversal", "23017", "file"]):
            return {
                "is_chainable": True,
                "transition_probability": 0.75,
                "causal_reason": f"Local file read via '{parent_vuln.title}' extracts configuration files and secrets to target '{child_vuln.title}'."
            }
        if any(w in parent_vuln.title.lower() for w in ["sql", "sqli"]):
            return {
                "is_chainable": True,
                "transition_probability": 0.85,
                "causal_reason": f"Database exfiltration via '{parent_vuln.title}' reveals backend credentials and internal network structure to target '{child_vuln.title}'."
            }
        return {"is_chainable": False, "transition_probability": 0.0, "causal_reason": "No causal link."}


    # --- 4. Remediation Agent Ability ---
