"""Unit tests for log redaction and formatting."""

from __future__ import annotations

import json
import logging

import pytest

from app.core.logging import JsonFormatter, RedactionFilter, redact


@pytest.mark.parametrize(
    ("raw", "secret"),
    [
        ("postgresql+psycopg://cti:s3cr3t@db:5432/cti", "s3cr3t"),
        ("Authorization: Bearer eyJhbGciOi.payload.sig", "eyJhbGciOi.payload.sig"),
        ("x-admin-key=abcdef0123456789", "abcdef0123456789"),
        ("password=hunter2 user=bob", "hunter2"),
        ('{"api_key": "sk-live-123"}', "sk-live-123"),
        ("ADMIN_API_KEY=very-long-admin-key", "very-long-admin-key"),
    ],
)
def test_redact_masks_secrets(raw: str, secret: str) -> None:
    assert secret not in redact(raw)


def test_redact_leaves_ordinary_text_alone() -> None:
    text = "GET /api/v1/health 200 in 3.1ms for CVE-2021-44228"
    assert redact(text) == text


def _record(msg: str, *args: object, **extra: object) -> logging.LogRecord:
    record = logging.LogRecord("test", logging.INFO, __file__, 1, msg, args, None)
    for key, value in extra.items():
        setattr(record, key, value)
    return record


def test_filter_redacts_message_args_and_extra_fields() -> None:
    record = _record("connecting to %s", "postgresql://u:pw123@h/db", detail="token=abc999")

    RedactionFilter().filter(record)

    assert "pw123" not in record.getMessage()
    assert "abc999" not in record.detail  # type: ignore[attr-defined]


def test_json_formatter_emits_one_json_object_with_extras() -> None:
    record = _record("request completed", status_code=200, path="/health")

    payload = json.loads(JsonFormatter().format(record))

    assert payload["message"] == "request completed"
    assert payload["level"] == "INFO"
    assert payload["status_code"] == 200
    assert payload["path"] == "/health"
