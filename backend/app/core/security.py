"""Admin authentication.

Administrative endpoints require the ``X-Admin-Key`` header. The comparison is
constant-time, and admin endpoints are disabled entirely (503) unless a strong key is
configured, so a missing configuration can never mean "open".
"""

from __future__ import annotations

import hmac
import logging
from typing import Annotated

from fastapi import Depends, Header, Request, status

from app.core.config import Settings
from app.core.exceptions import AppError

logger = logging.getLogger(__name__)


def get_settings_dep(request: Request) -> Settings:
    settings: Settings = request.app.state.settings
    return settings


def require_admin(
    request: Request,
    settings: Annotated[Settings, Depends(get_settings_dep)],
    x_admin_key: Annotated[str | None, Header(alias="X-Admin-Key")] = None,
) -> None:
    if not settings.admin_operations_enabled or settings.admin_api_key is None:
        raise AppError(
            "Administrative operations are disabled: ADMIN_API_KEY is not configured.",
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            code="admin_disabled",
        )
    if not x_admin_key:
        raise AppError(
            "Missing X-Admin-Key header.",
            status_code=status.HTTP_401_UNAUTHORIZED,
            code="admin_key_required",
        )
    expected = settings.admin_api_key.get_secret_value().encode()
    if not hmac.compare_digest(x_admin_key.encode(), expected):
        client = request.client.host if request.client else "unknown"
        logger.warning("Rejected admin request with an invalid key", extra={"client": client})
        raise AppError(
            "Invalid admin key.", status_code=status.HTTP_403_FORBIDDEN, code="admin_key_invalid"
        )
