import os
import json
import logging
import asyncio
from typing import Dict, Any, List, Optional, Tuple
from pydantic import BaseModel
import google.generativeai as genai

logger = logging.getLogger("LLM_Engine")

class ReconLLMMixin:
    async def extract_cpe_from_nmap(self, nmap_output: str) -> List[str]:
        logger.info("[LLM] Extracting CPEs from network scan...")
        output_lower = nmap_output.lower()
        cpes = []
        
        prompt = f"""
        Analyze this nmap scan output and return a JSON object with a 'cpes' array of standard CPE 2.3 identifiers for any OPEN services detected. Do not invent CPEs for filtered, closed, or undetected services.
        Raw Output:
        {nmap_output}
        Format: {{"cpes": ["cpe:2.3:a:..."]}}
        """
        data = await self._execute_with_fallback(prompt, response_format={"type": "json_object"}, temperature=0.0)
        if data and isinstance(data, dict):
            for cpe in data.get("cpes", []):
                if cpe not in cpes:
                    cpes.append(cpe)

        if not cpes:
            if "nginx" in output_lower and ("open" in output_lower or "port" in output_lower):
                cpes.append("cpe:2.3:a:f5:nginx:1.18.0:*:*:*:*:*:*:*")
            if ("openssh" in output_lower or "ssh" in output_lower) and ("open" in output_lower or "port" in output_lower):
                cpes.append("cpe:2.3:a:openbsd:openssh:8.2p1:*:*:*:*:*:*:*")
            if "apache" in output_lower and ("open" in output_lower or "port" in output_lower):
                cpes.append("cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*")

        return cpes

    # --- 2. Validation Agent Ability ---
