from typing import Any, List, Optional
from pydantic import SecretStr
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

    # Which reputation source to use when lookups are enabled: "mock" (default, offline) or "virustotal".
    # Live lookups are opt-in: they only happen when this is "virustotal" AND VIRUSTOTAL_API_KEY is set.
    # If "virustotal" is requested without a key, the app falls back to the labelled mock provider.
    THREAT_INTEL_PROVIDER: str = "mock"

    # VirusTotal public API. The key is a SecretStr so it can never be printed, logged or serialized by accident.
    VIRUSTOTAL_API_KEY: Optional[SecretStr] = None
    VIRUSTOTAL_TIMEOUT_SECONDS: float = 10.0           # per request (connect + read)
    VIRUSTOTAL_MALICIOUS_THRESHOLD: int = 3            # engines that must flag an indicator for MALICIOUS
    VIRUSTOTAL_MAX_LOOKUPS_PER_ALERT: int = 5          # network requests allowed per enrichment of one alert
    VIRUSTOTAL_REQUESTS_PER_MINUTE: int = 4            # public API quota
    VIRUSTOTAL_REQUESTS_PER_DAY: int = 500             # public API quota
    VIRUSTOTAL_CACHE_TTL_SECONDS: int = 86400          # in-memory cache of completed lookups
    # Indicators decoded from base64 in a PowerShell command line are sent to VirusTotal ONLY when this is true. They are
    # read from the command line itself, so the default keeps them local. Mock lookups are never affected.
    VIRUSTOTAL_LOOKUP_DECODED_INDICATORS: bool = False

    # Authentication. "disabled" (default, demo): no token, all actions allowed, reviewer names self-asserted.
    # "token": every request needs a bearer token from AUTH_TOKENS, a list of {"name", "role", "token"} objects where the
    # role is viewer, analyst or approver. Set AUTH_TOKENS as JSON in the environment; never commit real tokens.
    AUTH_MODE: str = "disabled"
    # Typed as a plain list on purpose: Pydantic would echo a bad value (possibly a token) in its error. The shape is checked by
    # validate_auth_config instead, whose messages never include a value.
    AUTH_TOKENS: List[Any] = []

    # Accounts mode (AUTH_MODE=accounts): people sign in with a username and password and get a session cookie.
    # See docs/SECURITY.md for the rules these numbers implement.
    SESSION_IDLE_MINUTES: int = 30           # a session ends after this long without use
    SESSION_ABSOLUTE_HOURS: int = 8          # and in any case this long after sign-in
    LOGIN_MAX_FAILURES: int = 5              # failed sign-ins for one username + client address ...
    LOGIN_LOCK_MINUTES: int = 15             # ... lock that pair for this long
    # None = the session cookie is Secure outside development and test (required in production). False is refused in production.
    SESSION_COOKIE_SECURE: Optional[bool] = None

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
