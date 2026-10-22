"""Structured logging and request logging middleware.

* ``configure_logging`` installs a JSON (or plain text) formatter on the root logger.
* ``RedactionFilter`` masks credentials that might slip into log messages, such as
  passwords in database URLs or ``Authorization`` header values.
* ``RequestContextMiddleware`` assigns each request an ID and logs one line per
  request with method, path, status and duration. Headers, query strings and bodies
  are deliberately not logged.
"""

from __future__ import annotations

import json
import logging
import re
import sys
import time
import uuid
from contextvars import ContextVar
from datetime import UTC, datetime
from typing import Any

from starlette.datastructures import MutableHeaders
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from app.core.config import LogFormat, Settings

REDACTED = "***"

request_id_var: ContextVar[str | None] = ContextVar("request_id", default=None)

# scheme://user:password@host -> scheme://user:***@host
_URL_CREDENTIALS = re.compile(r"(?P<prefix>[a-zA-Z][a-zA-Z0-9+.\-]*://[^:/\s@]+:)[^@\s]+@")
# password=..., api_key: ..., token=..., "secret": "..."
_KEY_VALUE_SECRET = re.compile(
    r"(?P<key>\b[\w-]*(?:password|passwd|secret|token|api[_-]?key|admin[_-]?key)[\w-]*\b"
    r"[\"']?\s*[:=]\s*[\"']?)(?P<value>[^\s\"',;&]+)",
    re.IGNORECASE,
)
# Authorization: Bearer abc / X-Admin-Key: abc
_AUTH_HEADER = re.compile(
    r"(?P<key>\b(?:authorization|proxy-authorization|x-admin-key|x-api-key|x-goog-api-key)\b"
    r"[\"']?\s*[:=]\s*"
    r"[\"']?)(?P<value>(?:bearer\s+|basic\s+)?[^\s\"',;]+)",
    re.IGNORECASE,
)

# Attributes present on every LogRecord; anything else was passed via ``extra=``.
# ``color_message`` is uvicorn's ANSI-coloured duplicate of the message.
_STANDARD_ATTRS = frozenset(
    vars(logging.LogRecord("", 0, "", 0, "", None, None)).keys()
    | {"message", "asctime", "color_message"}
)

# Google API keys (e.g. GEMINI_API_KEY) have a fixed shape, and may appear as ?key=...
_GOOGLE_API_KEY = re.compile(r"AIza[0-9A-Za-z_\-]{35}")
_URL_KEY_PARAM = re.compile(r"(?P<key>[?&]key=)(?P<value>[^\s&#\"']+)")

_VALID_REQUEST_ID = re.compile(r"^[A-Za-z0-9._-]{1,64}$")


def redact(text: str) -> str:
    """Mask credentials embedded in free text."""
    text = _URL_CREDENTIALS.sub(rf"\g<prefix>{REDACTED}@", text)
    text = _AUTH_HEADER.sub(rf"\g<key>{REDACTED}", text)
    text = _GOOGLE_API_KEY.sub(REDACTED, text)
    text = _URL_KEY_PARAM.sub(rf"\g<key>{REDACTED}", text)
    return _KEY_VALUE_SECRET.sub(rf"\g<key>{REDACTED}", text)


class RedactionFilter(logging.Filter):
    """Redact secrets from the rendered message and from string ``extra`` fields."""

    def filter(self, record: logging.LogRecord) -> bool:
        record.msg = redact(record.getMessage())
        record.args = None
        for key, value in vars(record).items():
            if key not in _STANDARD_ATTRS and isinstance(value, str):
                setattr(record, key, redact(value))
        return True


class JsonFormatter(logging.Formatter):
    """Render each record as a single JSON object."""

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "timestamp": datetime.fromtimestamp(record.created, UTC).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        request_id = getattr(record, "request_id", None) or request_id_var.get()
        if request_id:
            payload["request_id"] = request_id
        for key, value in vars(record).items():
            if key not in _STANDARD_ATTRS and key not in payload:
                payload[key] = value
        if record.exc_info:
            payload["exception"] = redact(self.formatException(record.exc_info))
        return json.dumps(payload, default=str)


class TextFormatter(logging.Formatter):
    def __init__(self) -> None:
        super().__init__("%(asctime)s %(levelname)-8s %(name)s: %(message)s")

    def formatException(self, ei: Any) -> str:  # noqa: N802 - stdlib name
        return redact(super().formatException(ei))


def configure_logging(settings: Settings) -> None:
    """Configure the root logger. Safe to call more than once."""
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(
        JsonFormatter() if settings.log_format is LogFormat.JSON else TextFormatter()
    )
    handler.addFilter(RedactionFilter())

    root = logging.getLogger()
    root.handlers.clear()
    root.addHandler(handler)
    root.setLevel(settings.log_level.value)

    # Route uvicorn's loggers through our handler; its access log is replaced by
    # RequestContextMiddleware, which never records query strings.
    for name in ("uvicorn", "uvicorn.error"):
        uv_logger = logging.getLogger(name)
        uv_logger.handlers.clear()
        uv_logger.propagate = True
    access = logging.getLogger("uvicorn.access")
    access.handlers.clear()
    access.propagate = False
    access.disabled = True


class RequestContextMiddleware:
    """Pure ASGI middleware that tags requests with an ID and logs their outcome."""

    def __init__(self, app: ASGIApp) -> None:
        self.app = app
        self.logger = logging.getLogger("app.request")

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        incoming = dict(scope.get("headers", [])).get(b"x-request-id", b"").decode("latin-1")
        request_id = incoming if _VALID_REQUEST_ID.match(incoming) else uuid.uuid4().hex
        # Stored on the scope so exception handlers outside this middleware can read it.
        scope.setdefault("state", {})["request_id"] = request_id
        token = request_id_var.set(request_id)

        status_code = 500
        start = time.perf_counter()

        async def send_wrapper(message: Message) -> None:
            nonlocal status_code
            if message["type"] == "http.response.start":
                status_code = message["status"]
                MutableHeaders(scope=message)["X-Request-ID"] = request_id
            await send(message)

        try:
            await self.app(scope, receive, send_wrapper)
        finally:
            duration_ms = round((time.perf_counter() - start) * 1000, 2)
            self.logger.info(
                "request completed",
                extra={
                    "request_id": request_id,
                    "method": scope.get("method"),
                    "path": scope.get("path"),
                    "status_code": status_code,
                    "duration_ms": duration_ms,
                },
            )
            request_id_var.reset(token)
