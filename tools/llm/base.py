import os
import json
import logging
import asyncio
from typing import Dict, Any, List, Optional, Tuple
from pydantic import BaseModel
import google.generativeai as genai

logger = logging.getLogger("LLM_Engine")

class BaseLLMClient:
    def __init__(self, api_key: str = None, base_url: str = None, model: str = None, fallback_models: List[str] = None):
        from core.config import settings
        resolved_key = api_key or settings.LLM_API_KEY or "none"
        resolved_base_url = base_url or settings.LLM_BASE_URL or None
        self.model = model or settings.LLM_MODEL or "gemini-3.6-flash"
        self.fallback_models = fallback_models or getattr(settings, "LLM_FALLBACK_MODELS", [
            "gemini-3.6-flash", "gemini-3.1-flash-lite", "gemini-flash-latest", "gpt-4o-mini"
        ])
        
        client_kwargs = {"api_key": resolved_key, "max_retries": 0}
        if resolved_base_url:
            client_kwargs["base_url"] = resolved_base_url
            
        self.client = AsyncOpenAI(**client_kwargs)
        self.is_quota_exhausted = False
        self.exhausted_models = set()

    def switch_model(self, new_model: str):
        """Allows dynamically switching active model mid-run or upon request."""
        old_model = self.model
        self.model = new_model
        if new_model in self.exhausted_models:
            self.exhausted_models.remove(new_model)
        self.is_quota_exhausted = False
        logger.info(f"[LLM] Explicitly switched model from '{old_model}' to '{new_model}'")

    def get_model_status(self) -> Dict[str, Any]:
        """Returns the current model status and active fallback pool."""
        return {
            "current_model": self.model,
            "fallback_models": self.fallback_models,
            "exhausted_models": list(self.exhausted_models),
            "is_quota_exhausted": self.is_quota_exhausted
        }

    async def _execute_with_fallback(self, prompt: str, response_format: Dict = None, temperature: float = 0.0) -> Any:
        """
        Executes a prompt across the active model and fallback chain.
        If a model hits a 429 rate limit or quota error, it automatically switches
        to the next available model in the fallback chain.
        """
        candidate_models = [self.model] + [m for m in self.fallback_models if m != self.model and m not in self.exhausted_models]
        
        for candidate in candidate_models:
            try:
                logger.info(f"[LLM] Querying model '{candidate}'...")
                response = await self.client.chat.completions.create(
                    model=candidate,
                    messages=[{"role": "user", "content": prompt}],
                    response_format=response_format,
                    temperature=temperature
                )
                if candidate != self.model:
                    logger.info(f"[LLM] Model switched from '{self.model}' -> '{candidate}' after earlier rate limits.")
                    self.model = candidate
                
                content = response.choices[0].message.content
                if response_format and response_format.get("type") == "json_object":
                    return json.loads(content)
                return content
            except Exception as e:
                err_lower = str(e).lower()
                if "429" in err_lower or "quota" in err_lower or "rate" in err_lower or "resource_exhausted" in err_lower:
                    logger.warning(f"[LLM] Rate limit hit for model '{candidate}' ({e}). Switching to next fallback model...")
                    self.exhausted_models.add(candidate)
                    continue
                elif "not found" in err_lower or "unsupported" in err_lower:
                    logger.warning(f"[LLM] Model '{candidate}' not supported on current base URL: {e}. Skipping...")
                    self.exhausted_models.add(candidate)
                    continue
                else:
                    logger.warning(f"[LLM] Call error on '{candidate}': {e}. Trying fallback...")
                    continue
                    
        self.is_quota_exhausted = True
        return None

    # --- 1. VAPT Agent Ability ---
