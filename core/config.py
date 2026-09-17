import os
from dotenv import load_dotenv

# Load key-value pairs from .env into os.environ
load_dotenv()

class Settings:
    # LLM Settings (Configured for Google Gemini 3.5 Flash-Lite)
    LLM_API_KEY: str = os.getenv("LLM_API_KEY", os.getenv("OPENAI_API_KEY", ""))
    LLM_BASE_URL: str = os.getenv("LLM_BASE_URL", "https://generativelanguage.googleapis.com/v1beta/openai/")
    LLM_MODEL: str = os.getenv("LLM_MODEL", "gemini-3.6-flash")
    # Fallback models ordered by priority when encountering HTTP 429 / rate limits / quota exhaustion
    LLM_FALLBACK_MODELS: list = [
        m.strip() for m in os.getenv(
            "LLM_FALLBACK_MODELS", 
            "gemini-3.6-flash,gemini-3.1-pro-preview,gemini-3.5-flash-lite,gpt-4o-mini"
        ).split(",") if m.strip()
    ]
    OPENAI_API_KEY: str = os.getenv("OPENAI_API_KEY", "")

    # Threat Intelligence & OSINT APIs
    VT_API_KEY: str = os.getenv("VT_API_KEY", "")
    HIBP_API_KEY: str = os.getenv("HIBP_API_KEY", "")
    NVD_API_KEY: str = os.getenv("NVD_API_KEY", "")

    @property
    def has_llm(self) -> bool:
        if "localhost" in self.LLM_BASE_URL or "127.0.0.1" in self.LLM_BASE_URL:
            return True
        return bool(self.LLM_API_KEY and not self.LLM_API_KEY.startswith("sk-proj-your"))

# Global settings instance
settings = Settings()