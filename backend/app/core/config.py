"""Environment-based application configuration.

Settings are read from environment variables (and an optional ``.env`` file)
and validated once at startup. Secrets are stored as ``SecretStr`` so they are
masked in ``repr()`` output and never end up in logs by accident.
"""

from __future__ import annotations

from enum import StrEnum
from functools import lru_cache
from typing import Annotated, Any, Self

from pydantic import (
    Field,
    PostgresDsn,
    SecretStr,
    ValidationError,
    field_validator,
    model_validator,
)
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict

from app.core.exceptions import ConfigurationError

# Minimum length for the admin key outside development; long enough to resist guessing.
MIN_ADMIN_KEY_LENGTH = 32

# Values that must never be accepted as a real admin key.
_PLACEHOLDER_SECRETS = frozenset({"", "change-me", "changeme", "replace-me", "secret", "admin"})


class Environment(StrEnum):
    DEVELOPMENT = "development"
    TEST = "test"
    PRODUCTION = "production"


class LogLevel(StrEnum):
    DEBUG = "DEBUG"
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"


class LogFormat(StrEnum):
    JSON = "json"
    TEXT = "text"


class Settings(BaseSettings):
    """Validated application settings."""

    model_config = SettingsConfigDict(
        # Relative to the working directory: the repository-root .env when running from
        # backend/, with an optional backend/.env taking precedence. Real environment
        # variables always win over both.
        env_file=("../.env", ".env"),
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False,
    )

    app_name: str = Field(default="Cyber Threat Intelligence API", min_length=1, max_length=100)
    environment: Environment = Environment.DEVELOPMENT
    log_level: LogLevel = LogLevel.INFO
    log_format: LogFormat = LogFormat.JSON
    api_v1_prefix: str = "/api/v1"
    # Comma-separated in the environment, e.g. "http://localhost:3000,http://127.0.0.1:3000".
    cors_origins: Annotated[list[str], NoDecode] = Field(default_factory=list)

    database_url: SecretStr
    db_pool_size: int = Field(default=5, ge=1, le=50)
    db_max_overflow: int = Field(default=5, ge=0, le=50)
    db_connect_timeout_seconds: int = Field(default=5, ge=1, le=60)
    db_statement_timeout_ms: int = Field(default=5000, ge=100, le=600_000)

    # Required for administrative operations (e.g. triggering ingestion in a later phase).
    admin_api_key: SecretStr | None = None

    @field_validator("log_level", mode="before")
    @classmethod
    def _normalise_log_level(cls, value: Any) -> Any:
        return value.upper() if isinstance(value, str) else value

    @field_validator("api_v1_prefix")
    @classmethod
    def _validate_prefix(cls, value: str) -> str:
        value = value.rstrip("/")
        if not value.startswith("/") or len(value) < 2:
            raise ValueError("must start with '/' and not be empty, e.g. '/api/v1'")
        return value

    @field_validator("cors_origins", mode="before")
    @classmethod
    def _split_cors_origins(cls, value: Any) -> Any:
        if isinstance(value, str):
            return [origin.strip().rstrip("/") for origin in value.split(",") if origin.strip()]
        return value

    @field_validator("cors_origins")
    @classmethod
    def _validate_cors_origins(cls, origins: list[str]) -> list[str]:
        for origin in origins:
            if origin != "*" and not origin.startswith(("http://", "https://")):
                raise ValueError(f"invalid origin {origin!r}; expected scheme://host[:port]")
        return origins

    @field_validator("database_url")
    @classmethod
    def _validate_database_url(cls, value: SecretStr) -> SecretStr:
        raw = value.get_secret_value()
        try:
            url = PostgresDsn(raw)
        except ValueError:
            # Re-raise without echoing the URL, which may contain a password.
            raise ValueError(
                "must be a PostgreSQL URL such as "
                "postgresql+psycopg://user:password@localhost:5432/dbname"
            ) from None
        if url.scheme not in {"postgresql", "postgresql+psycopg"}:
            raise ValueError("scheme must be 'postgresql+psycopg' (or 'postgresql')")
        return value

    @model_validator(mode="after")
    def _validate_production(self) -> Self:
        """Apply stricter rules outside development and test."""
        if self.environment is not Environment.PRODUCTION:
            return self

        problems: list[str] = []
        if "*" in self.cors_origins:
            problems.append("CORS_ORIGINS must not contain '*' in production")
        if any(o.startswith("http://") for o in self.cors_origins):
            problems.append("CORS_ORIGINS must use https:// origins in production")
        key = self.admin_api_key.get_secret_value() if self.admin_api_key else ""
        if key.lower() in _PLACEHOLDER_SECRETS or len(key) < MIN_ADMIN_KEY_LENGTH:
            problems.append(
                f"ADMIN_API_KEY must be set to a random value of at least "
                f"{MIN_ADMIN_KEY_LENGTH} characters in production"
            )
        if self.log_level is LogLevel.DEBUG:
            problems.append("LOG_LEVEL must not be DEBUG in production")
        if problems:
            raise ValueError("; ".join(problems))
        return self

    @property
    def is_production(self) -> bool:
        return self.environment is Environment.PRODUCTION

    @property
    def admin_operations_enabled(self) -> bool:
        """Admin endpoints (added in later phases) are disabled unless a usable key is set."""
        if self.admin_api_key is None:
            return False
        key = self.admin_api_key.get_secret_value()
        return key.lower() not in _PLACEHOLDER_SECRETS and len(key) >= MIN_ADMIN_KEY_LENGTH


def load_settings(**overrides: Any) -> Settings:
    """Build settings, turning validation failures into an actionable error.

    The error message names the offending environment variables but never
    includes their values.
    """
    try:
        return Settings(**overrides)
    except ValidationError as exc:
        lines = []
        for error in exc.errors(include_input=False, include_url=False):
            field = ".".join(str(part) for part in error["loc"]) or "settings"
            env_name = field.upper() if error["loc"] else "configuration"
            message = error["msg"].removeprefix("Value error, ")
            lines.append(f"  - {env_name}: {message}")
        raise ConfigurationError(
            "Invalid application configuration:\n"
            + "\n".join(lines)
            + "\nSet these environment variables or add them to .env (see .env.example)."
        ) from None


@lru_cache
def get_settings() -> Settings:
    """Return the process-wide settings instance."""
    return load_settings()
