import os
from typing import List
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    PROJECT_NAME: str = "SOCMind AI"
    VERSION: str = "1.0.0"
    API_V1_STR: str = "/api/v1"
    ENVIRONMENT: str = "development"
    DEBUG: bool = True

    # Database Configuration
    DATABASE_URL: str = "sqlite:///./socmind.db"

    # CORS Configuration
    CORS_ORIGINS: List[str] = [
        "http://localhost:5173",
        "http://localhost:3000",
        "http://127.0.0.1:5173",
        "http://127.0.0.1:3000",
    ]

    # LLM Settings (Configurable placeholders)
    LLM_PROVIDER: str = "mock"
    LLM_MODEL_NAME: str = "gemini-2.5-flash-mock"
    LLM_API_KEY: str = "YOUR_API_KEY_PLACEHOLDER"

    # Threat intelligence: True uses the built-in LOCAL MOCK lookups. False means "no provider available":
    # IOCs are still extracted but no reputation lookup is performed (no live provider is implemented).
    THREAT_INTEL_MOCK_MODE: bool = True

    # Logging
    LOG_LEVEL: str = "INFO"

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore"
    )


settings = Settings()

# Response actions are never executed against real systems. This is a constant on purpose, not a setting:
# there is no real response integration, so there is nothing a configuration value could safely enable.
EXECUTION_MODE = "simulation_only"
