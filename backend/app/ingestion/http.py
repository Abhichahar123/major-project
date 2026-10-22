"""HTTP client for upstream sources.

Every request:

* goes only to an allowlisted host (derived from the configured source URLs), which stops
  ingestion from being pointed at arbitrary or internal addresses;
* has connect/read timeouts and a response-size cap;
* is retried with exponential backoff and jitter on timeouts, connection errors, 429 and
  5xx responses, honouring ``Retry-After`` (capped).
"""

from __future__ import annotations

import json
import logging
import random
import time
from collections.abc import Callable, Iterable, Mapping
from typing import Any
from urllib.parse import urlsplit

import httpx

logger = logging.getLogger(__name__)

RETRYABLE_STATUS = frozenset({429, 500, 502, 503, 504})
MAX_RETRY_AFTER_SECONDS = 60.0


class SourceError(Exception):
    """An upstream request failed and should not (or can no longer) be retried."""


class SourceNotFoundError(SourceError):
    """The upstream returned 404 for the requested record."""


class DisallowedHostError(SourceError):
    """The URL's host is not on the ingestion allowlist."""


class ResponseTooLargeError(SourceError):
    """The response exceeded the configured size cap."""


class SourceHttpClient:
    def __init__(
        self,
        *,
        allowed_hosts: Iterable[str],
        timeout_seconds: float = 30.0,
        max_retries: int = 4,
        backoff_base_seconds: float = 1.0,
        backoff_max_seconds: float = 30.0,
        max_response_bytes: int = 100 * 1024 * 1024,
        user_agent: str = "cti-platform-ingestion/0.1",
        transport: httpx.BaseTransport | None = None,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        self.allowed_hosts = frozenset(h.lower() for h in allowed_hosts)
        self.max_retries = max_retries
        self.backoff_base_seconds = backoff_base_seconds
        self.backoff_max_seconds = backoff_max_seconds
        self.max_response_bytes = max_response_bytes
        self._sleep = sleep
        self._client = httpx.Client(
            timeout=httpx.Timeout(timeout_seconds, connect=min(10.0, timeout_seconds)),
            headers={"User-Agent": user_agent, "Accept": "application/json"},
            follow_redirects=False,  # a redirect could leave the allowlist
            transport=transport,
        )

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> SourceHttpClient:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def _check_url(self, url: str) -> None:
        parts = urlsplit(url)
        if parts.scheme != "https" or (parts.hostname or "").lower() not in self.allowed_hosts:
            raise DisallowedHostError(f"host not allowed for ingestion: {parts.hostname!r}")

    def _delay(self, attempt: int, retry_after: str | None) -> float:
        if retry_after:
            try:
                return min(max(float(retry_after), 0.0), MAX_RETRY_AFTER_SECONDS)
            except ValueError:
                pass  # HTTP-date form: fall back to exponential backoff
        base = min(self.backoff_max_seconds, self.backoff_base_seconds * (2.0**attempt))
        return base + random.uniform(0, base / 2)  # noqa: S311 - jitter, not cryptography

    def get_bytes(
        self,
        url: str,
        *,
        params: Mapping[str, Any] | None = None,
        headers: Mapping[str, str] | None = None,
        max_bytes: int | None = None,
    ) -> bytes:
        self._check_url(url)
        limit = max_bytes or self.max_response_bytes
        last_error: Exception | None = None
        for attempt in range(self.max_retries + 1):
            retry_after: str | None = None
            try:
                with self._client.stream("GET", url, params=params, headers=headers) as resp:
                    if resp.status_code == 404:
                        raise SourceNotFoundError(f"not found: {urlsplit(url).path}")
                    if resp.status_code in RETRYABLE_STATUS:
                        retry_after = resp.headers.get("Retry-After")
                        last_error = SourceError(f"HTTP {resp.status_code} from {resp.url.host}")
                    elif resp.status_code >= 300:  # includes redirects, which are never followed
                        raise SourceError(f"HTTP {resp.status_code} from {resp.url.host}")
                    else:
                        declared = resp.headers.get("Content-Length")
                        if declared and declared.isdigit() and int(declared) > limit:
                            raise ResponseTooLargeError(f"response exceeds {limit} bytes")
                        chunks: list[bytes] = []
                        size = 0
                        for chunk in resp.iter_bytes():
                            size += len(chunk)
                            if size > limit:
                                raise ResponseTooLargeError(f"response exceeds {limit} bytes")
                            chunks.append(chunk)
                        return b"".join(chunks)
            except (httpx.TimeoutException, httpx.TransportError) as exc:
                last_error = SourceError(
                    f"{type(exc).__name__} contacting {urlsplit(url).hostname}"
                )
            if attempt < self.max_retries:
                delay = self._delay(attempt, retry_after)
                logger.warning(
                    "Retrying upstream request",
                    extra={
                        "host": urlsplit(url).hostname,
                        "attempt": attempt + 1,
                        "delay_s": round(delay, 2),
                        "reason": str(last_error),
                    },
                )
                self._sleep(delay)
        raise SourceError(f"giving up after {self.max_retries + 1} attempts: {last_error}")

    def get_json(
        self,
        url: str,
        *,
        params: Mapping[str, Any] | None = None,
        headers: Mapping[str, str] | None = None,
        max_bytes: int | None = None,
    ) -> Any:
        body = self.get_bytes(url, params=params, headers=headers, max_bytes=max_bytes)
        try:
            return json.loads(body)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise SourceError(f"invalid JSON from {urlsplit(url).hostname}") from exc


def hosts_of(urls: Iterable[str]) -> set[str]:
    return {(urlsplit(u).hostname or "").lower() for u in urls if u}
