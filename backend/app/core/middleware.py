"""Security headers and request-body size limits (pure ASGI middleware)."""

from __future__ import annotations

import json

from starlette.datastructures import MutableHeaders
from starlette.types import ASGIApp, Message, Receive, Scope, Send

_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Cross-Origin-Resource-Policy": "same-site",
    # The API only returns JSON: nothing may be loaded, framed or executed from it.
    "Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'",
}
# Swagger UI (development only) loads its scripts and styles from a CDN.
_DOCS_PREFIXES = ("/docs",)


class SecurityHeadersMiddleware:
    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        is_docs = str(scope.get("path", "")).startswith(_DOCS_PREFIXES)

        async def send_wrapper(message: Message) -> None:
            if message["type"] == "http.response.start":
                headers = MutableHeaders(scope=message)
                for name, value in _HEADERS.items():
                    if name == "Content-Security-Policy" and is_docs:
                        continue
                    headers.setdefault(name, value)
            await send(message)

        await self.app(scope, receive, send_wrapper)


class BodySizeLimitMiddleware:
    """Reject request bodies above ``max_bytes`` (413) before handlers read them.

    Uses Content-Length when present and also counts streamed bytes, so chunked uploads
    without a length cannot exceed the limit either.
    """

    def __init__(self, app: ASGIApp, max_bytes: int) -> None:
        self.app = app
        self.max_bytes = max_bytes

    async def _reject(self, send: Send) -> None:
        body = json.dumps(
            {
                "type": "about:blank",
                "title": "Content Too Large",
                "status": 413,
                "detail": f"Request body exceeds {self.max_bytes // 1024} KB.",
                "code": "body_too_large",
            }
        ).encode()
        await send(
            {
                "type": "http.response.start",
                "status": 413,
                "headers": [
                    (b"content-type", b"application/problem+json"),
                    (b"content-length", str(len(body)).encode()),
                ],
            }
        )
        await send({"type": "http.response.body", "body": body})

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        length = dict(scope.get("headers", [])).get(b"content-length")
        if length is not None:
            try:
                too_large = int(length) > self.max_bytes
            except ValueError:
                too_large = True  # a malformed length is not trusted
            if too_large:
                await self._reject(send)
                return

        received = 0
        exceeded = False
        replaced = False

        async def counting_receive() -> Message:
            nonlocal received, exceeded
            message = await receive()
            if message["type"] == "http.request":
                received += len(message.get("body", b""))
                if received > self.max_bytes:
                    # Stop passing data on; whatever the app answers is replaced by a 413.
                    exceeded = True
                    return {"type": "http.request", "body": b"", "more_body": False}
            return message

        async def guarded_send(message: Message) -> None:
            nonlocal replaced
            if exceeded:
                if message["type"] == "http.response.start" and not replaced:
                    replaced = True
                    await self._reject(send)
                return
            await send(message)

        await self.app(scope, counting_receive, guarded_send)
