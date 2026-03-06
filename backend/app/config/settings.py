"""
Commit 18: feat: add environment variable config loader with defaults
Loads all runtime settings from .env with safe fallback defaults.
"""

import os
from dotenv import load_dotenv

load_dotenv()


def _bool(key: str, default: bool) -> bool:
    val = os.getenv(key, "").lower()
    if val in ("1", "true", "yes"):
        return True
    if val in ("0", "false", "no"):
        return False
    return default


class Settings:
    """Central application settings loaded from environment variables."""

    # --- Ollama ---
    OLLAMA_TIMEOUT: int = int(os.getenv("OLLAMA_TIMEOUT", "30"))
    OLLAMA_HOST: str = os.getenv("OLLAMA_HOST", "http://localhost:11434")
    PREFERRED_MODELS: list[str] = ["llama3-gpu", "llama3", "mistral"]

    # --- Security ---
    MAX_PROMPT_LENGTH: int = int(os.getenv("MAX_PROMPT_LENGTH", "4096"))
    RATE_LIMIT_PER_MINUTE: int = int(os.getenv("RATE_LIMIT_PER_MINUTE", "30"))
    SECURITY_ENABLED_DEFAULT: bool = _bool("SECURITY_ENABLED_DEFAULT", True)
    THREAT_SCORE_THRESHOLD: float = float(os.getenv("THREAT_SCORE_THRESHOLD", "0.5"))

    # --- Logging ---
    LOG_LEVEL: str = os.getenv("LOG_LEVEL", "INFO").upper()
    LOG_MAX_BYTES: int = int(os.getenv("LOG_MAX_BYTES", str(5 * 1024 * 1024)))  # 5 MB
    LOG_BACKUP_COUNT: int = int(os.getenv("LOG_BACKUP_COUNT", "3"))
    LOG_JSON_FORMAT: bool = _bool("LOG_JSON_FORMAT", False)

    # --- API ---
    API_HOST: str = os.getenv("API_HOST", "0.0.0.0")
    API_PORT: int = int(os.getenv("API_PORT", "8000"))
    CORS_ORIGINS: list[str] = os.getenv("CORS_ORIGINS", "*").split(",")

    # --- Stats ---
    STATS_DUMP_ON_SHUTDOWN: bool = _bool("STATS_DUMP_ON_SHUTDOWN", True)


# Singleton instance used everywhere in the app
settings = Settings()
