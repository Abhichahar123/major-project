"""Application errors and centralized exception handlers.

Every error response uses the RFC 9457 "problem details" format::

    {"type": "about:blank", "title": "Not Found", "status": 404,
     "detail": "...", "code": "not_found", "request_id": "..."}

Unexpected exceptions are logged server-side with their traceback, while the
client only receives a generic message and the request ID for correlation.
"""

from __future__ import annotations

import logging
from http import HTTPStatus
from typing import Any

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

logger = logging.getLogger(__name__)

PROBLEM_JSON = "application/problem+json"


class ConfigurationError(RuntimeError):
    """Raised at startup when required settings are missing or invalid."""


class AppError(Exception):
    """Base class for expected, client-facing application errors."""

    status_code: int = HTTPStatus.INTERNAL_SERVER_ERROR
    code: str = "internal_error"

    def __init__(self, detail: str, *, status_code: int | None = None, code: str | None = None):
        super().__init__(detail)
        self.detail = detail
        if status_code is not None:
            self.status_code = status_code
        if code is not None:
            self.code = code


def _request_id(request: Request) -> str | None:
    value = request.scope.get("state", {}).get("request_id")
    return value if isinstance(value, str) else None


def problem_response(
    request: Request,
    status_code: int,
    detail: str,
    code: str,
    extra: dict[str, Any] | None = None,
) -> JSONResponse:
    request_id = _request_id(request)
    body: dict[str, Any] = {
        "type": "about:blank",
        "title": HTTPStatus(status_code).phrase,
        "status": status_code,
        "detail": detail,
        "code": code,
        "request_id": request_id,
    }
    if extra:
        body.update(extra)
    headers = {"X-Request-ID": request_id} if request_id else None
    return JSONResponse(body, status_code=status_code, media_type=PROBLEM_JSON, headers=headers)


async def _app_error_handler(request: Request, exc: AppError) -> JSONResponse:
    return problem_response(request, exc.status_code, exc.detail, exc.code)


async def _http_exception_handler(request: Request, exc: StarletteHTTPException) -> JSONResponse:
    status = HTTPStatus(exc.status_code)
    detail = exc.detail if isinstance(exc.detail, str) else status.phrase
    code = status.phrase.lower().replace(" ", "_").replace("-", "_")
    response = problem_response(request, exc.status_code, detail, code)
    if exc.headers:
        response.headers.update(exc.headers)
    return response


async def _validation_error_handler(request: Request, exc: RequestValidationError) -> JSONResponse:
    # Report where and why validation failed, but not the submitted input itself.
    errors = [
        {"loc": list(err.get("loc", ())), "msg": err.get("msg", ""), "type": err.get("type", "")}
        for err in exc.errors()
    ]
    return problem_response(
        request,
        HTTPStatus.UNPROCESSABLE_ENTITY,
        "Request validation failed.",
        "validation_error",
        extra={"errors": errors},
    )


async def _unhandled_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    logger.error(
        "Unhandled exception",
        exc_info=exc,
        extra={"request_id": _request_id(request), "path": request.url.path},
    )
    return problem_response(
        request,
        HTTPStatus.INTERNAL_SERVER_ERROR,
        "An unexpected error occurred. Quote the request ID when reporting this issue.",
        "internal_error",
    )


def register_exception_handlers(app: FastAPI) -> None:
    # The decorator form accepts handlers typed with their specific exception class.
    app.exception_handler(AppError)(_app_error_handler)
    app.exception_handler(StarletteHTTPException)(_http_exception_handler)
    app.exception_handler(RequestValidationError)(_validation_error_handler)
    app.exception_handler(Exception)(_unhandled_exception_handler)
