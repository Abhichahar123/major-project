"""Environment-based application configuration.

Settings are read from environment variables (and an optional ``.env`` file)
and validated once at startup. Secrets are stored as ``SecretStr`` so they are
masked in ``repr()`` output and never end up in logs by accident.
"""

from __future__ import annotations

from enum import StrEnum
from functools import lru_cache
from typing import Annotated, Any, Literal, Self
from urllib.parse import urlsplit

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


def _require_https(url: str) -> str:
    parts = urlsplit(url)
    if parts.scheme != "https" or not parts.hostname:
        raise ValueError(f"must be an https:// URL, got {url!r}")
    return url


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

    # Required for administrative operations such as triggering ingestion jobs.
    admin_api_key: SecretStr | None = None

    # --- Embeddings and LLM ------------------------------------------------------------
    # hashing: built-in lexical embedder (no download, not semantic; development/tests).
    # ollama: real embeddings from a local Ollama server, e.g. nomic-embed-text (768-d).
    # none: keyword search only.
    embedding_provider: Literal["hashing", "ollama", "none"] = "hashing"
    embedding_model: str = Field(default="nomic-embed-text", min_length=1, max_length=200)
    embedding_batch_size: int = Field(default=32, ge=1, le=512)
    embedding_timeout_seconds: float = Field(default=60.0, ge=1, le=600)
    # Local inference server; plain http is expected on localhost or the Compose network.
    ollama_base_url: str = "http://localhost:11434"

    # ollama (default): local model via Ollama. openai_compatible: a hosted endpoint, used only
    # when LLM_BASE_URL and LLM_API_KEY are set (evidence is then sent to that provider).
    # mock: deterministic answers for automated tests. none: evidence-only answers.
    llm_provider: Literal["ollama", "openai_compatible", "mock", "none"] = "ollama"
    llm_model: str = Field(default="llama3.1:8b", min_length=1, max_length=200)
    llm_base_url: str | None = None
    llm_api_key: SecretStr | None = None
    llm_timeout_seconds: float = Field(default=90.0, ge=1, le=600)
    llm_max_tokens: int = Field(default=700, ge=64, le=4096)
    llm_temperature: float = Field(default=0.1, ge=0.0, le=1.0)
    rag_top_k: int = Field(default=8, ge=1, le=20)
    rag_max_context_chars: int = Field(default=12_000, ge=1000, le=100_000)
    rag_max_answer_chars: int = Field(default=6000, ge=500, le=50_000)

    # Dependency analysis: also query api.osv.dev for advisories missing from the local
    # export. Off by default: it sends package names and versions to a third party.
    osv_online_lookup: bool = False

    # Largest accepted request body (uploads are additionally limited to 512 KB).
    max_request_body_bytes: int = Field(default=1024 * 1024, ge=64 * 1024, le=50 * 1024 * 1024)

    # --- Rate limits (requests per minute per client; 0 disables) ----------------------
    rate_limit_search_per_minute: int = Field(default=120, ge=0, le=10_000)
    rate_limit_chat_per_minute: int = Field(default=10, ge=0, le=1000)
    rate_limit_dependencies_per_minute: int = Field(default=20, ge=0, le=1000)
    rate_limit_admin_per_minute: int = Field(default=10, ge=0, le=1000)

    # --- Ingestion --------------------------------------------------------------------
    # Feeds are tried in order; the GitHub mirror is the official CISA kev-data repository.
    kev_feed_urls: Annotated[list[str], NoDecode] = Field(
        default_factory=lambda: [
            "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
            "https://raw.githubusercontent.com/cisagov/kev-data/main/known_exploited_vulnerabilities.json",
        ]
    )
    cve5_base_url: str = "https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves"
    nvd_api_url: str = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    nvd_api_key: SecretStr | None = None
    attack_stix_url: str = (
        "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/"
        "enterprise-attack/enterprise-attack.json"
    )
    capec_stix_url: str = (
        "https://raw.githubusercontent.com/mitre/cti/master/capec/2.1/stix-capec.json"
    )
    osv_data_base_url: str = "https://storage.googleapis.com/osv-vulnerabilities"
    osv_api_url: str = "https://api.osv.dev/v1"
    ingestion_http_timeout_seconds: float = Field(default=30.0, ge=1, le=300)
    ingestion_max_retries: int = Field(default=4, ge=0, le=10)
    ingestion_backoff_base_seconds: float = Field(default=1.0, ge=0, le=60)
    ingestion_max_response_mb: int = Field(default=150, ge=1, le=1024)
    ingestion_concurrency: int = Field(default=8, ge=1, le=32)
    ingestion_statement_timeout_ms: int = Field(default=120_000, ge=1000, le=3_600_000)
    ingestion_stale_job_minutes: int = Field(default=120, ge=5, le=10_080)

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

    @field_validator("kev_feed_urls", mode="before")
    @classmethod
    def _split_urls(cls, value: Any) -> Any:
        if isinstance(value, str):
            return [url.strip() for url in value.split(",") if url.strip()]
        return value

    @field_validator("kev_feed_urls")
    @classmethod
    def _validate_feed_urls(cls, urls: list[str]) -> list[str]:
        if not urls:
            raise ValueError("at least one URL is required")
        for url in urls:
            _require_https(url)
        return urls

    @field_validator(
        "cve5_base_url",
        "nvd_api_url",
        "attack_stix_url",
        "capec_stix_url",
        "osv_data_base_url",
        "osv_api_url",
    )
    @classmethod
    def _validate_source_url(cls, url: str) -> str:
        return _require_https(url).rstrip("/")

    @field_validator("ollama_base_url")
    @classmethod
    def _validate_ollama_url(cls, url: str) -> str:
        parts = urlsplit(url)
        if parts.scheme not in {"http", "https"} or not parts.hostname:
            raise ValueError("must be an http(s) URL such as http://localhost:11434")
        return url.rstrip("/")

    @model_validator(mode="after")
    def _validate_llm(self) -> Self:
        if self.llm_provider == "openai_compatible":
            if not self.llm_base_url or not self.llm_api_key:
                raise ValueError(
                    "LLM_PROVIDER=openai_compatible requires LLM_BASE_URL and LLM_API_KEY"
                )
            _require_https(self.llm_base_url)
        return self

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
        if self.llm_provider == "mock":
            problems.append("LLM_PROVIDER=mock is for tests only and not allowed in production")
        if self.log_level is LogLevel.DEBUG:
            problems.append("LOG_LEVEL must not be DEBUG in production")
        if problems:
            raise ValueError("; ".join(problems))
        return self

    @property
    def is_production(self) -> bool:
        return self.environment is Environment.PRODUCTION

    @property
    def ingestion_allowed_hosts(self) -> set[str]:
        """Hosts ingestion may contact: exactly those of the configured source URLs."""
        urls = [
            *self.kev_feed_urls,
            self.cve5_base_url,
            self.nvd_api_url,
            self.attack_stix_url,
            self.capec_stix_url,
            self.osv_data_base_url,
            self.osv_api_url,
        ]
        return {(urlsplit(u).hostname or "").lower() for u in urls}

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
