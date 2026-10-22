"""Unit tests for configuration loading and validation."""

from __future__ import annotations

import pytest

from app.core.config import Environment, LogLevel, load_settings
from app.core.exceptions import ConfigurationError
from tests.conftest import make_settings

STRONG_KEY = "k" * 40


def test_defaults_are_applied() -> None:
    settings = make_settings()

    assert settings.environment is Environment.TEST
    assert settings.api_v1_prefix == "/api/v1"
    assert settings.cors_origins == []
    assert settings.log_level is LogLevel.INFO


def test_missing_database_url_gives_actionable_error(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("DATABASE_URL", raising=False)

    with pytest.raises(ConfigurationError) as excinfo:
        load_settings(_env_file=None)

    message = str(excinfo.value)
    assert "DATABASE_URL" in message
    assert ".env.example" in message


def test_invalid_database_url_error_does_not_echo_secret() -> None:
    with pytest.raises(ConfigurationError) as excinfo:
        load_settings(_env_file=None, database_url="mysql://root:hunter2@db/app")

    assert "DATABASE_URL" in str(excinfo.value)
    assert "hunter2" not in str(excinfo.value)


def test_database_url_is_masked_in_repr() -> None:
    settings = make_settings()
    assert "test-password" not in repr(settings)


def test_invalid_log_level_is_rejected() -> None:
    with pytest.raises(ConfigurationError, match="LOG_LEVEL"):
        load_settings(_env_file=None, database_url=make_settings().database_url, log_level="loud")


def test_log_level_is_case_insensitive() -> None:
    assert make_settings(log_level="debug").log_level is LogLevel.DEBUG


def test_cors_origins_parsed_from_comma_separated_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("CORS_ORIGINS", "http://localhost:3000, http://127.0.0.1:8080/")

    settings = make_settings()

    assert settings.cors_origins == ["http://localhost:3000", "http://127.0.0.1:8080"]


def test_cors_origin_without_scheme_is_rejected() -> None:
    with pytest.raises(ValueError, match="invalid origin"):
        make_settings(cors_origins=["localhost:3000"])


def test_api_prefix_must_start_with_slash() -> None:
    with pytest.raises(ValueError, match="must start with"):
        make_settings(api_v1_prefix="api/v1")


def test_production_requires_admin_key() -> None:
    with pytest.raises(ValueError, match="ADMIN_API_KEY"):
        make_settings(environment="production", cors_origins=["https://app.example.org"])


def test_production_rejects_placeholder_admin_key() -> None:
    with pytest.raises(ValueError, match="ADMIN_API_KEY"):
        make_settings(environment="production", admin_api_key="change-me")


def test_production_rejects_wildcard_cors() -> None:
    with pytest.raises(ValueError, match="must not contain"):
        make_settings(environment="production", admin_api_key=STRONG_KEY, cors_origins=["*"])


def test_production_rejects_plain_http_origins() -> None:
    with pytest.raises(ValueError, match="https://"):
        make_settings(
            environment="production",
            admin_api_key=STRONG_KEY,
            cors_origins=["http://app.example.org"],
        )


def test_valid_production_settings() -> None:
    settings = make_settings(
        environment="production",
        admin_api_key=STRONG_KEY,
        cors_origins=["https://app.example.org"],
    )
    assert settings.is_production
    assert settings.admin_operations_enabled


def test_development_allows_missing_admin_key_but_disables_admin_ops() -> None:
    settings = make_settings(environment="development")
    assert settings.admin_operations_enabled is False


def test_short_admin_key_does_not_enable_admin_ops() -> None:
    assert make_settings(admin_api_key="short").admin_operations_enabled is False
