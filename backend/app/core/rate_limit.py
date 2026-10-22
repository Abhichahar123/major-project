"""In-process sliding-window rate limiting.

Suitable for a single API process (the development and demo deployment). Limits are
per client address and per bucket (``search``, ``chat``, ``dependencies``, ``admin``). The
client address is the socket peer: ``X-Forwarded-For`` is ignored because it is
client-controlled unless a trusted proxy sets it. Multi-process deployments need a shared
store such as Redis instead.
"""

from __future__ import annotations

import threading
import time
from collections import deque
from collections.abc import Callable

from fastapi import Request, status

from app.core.exceptions import AppError

MAX_TRACKED_CLIENTS = 10_000


class RateLimiter:
    def __init__(self, clock: Callable[[], float] = time.monotonic) -> None:
        self._clock = clock
        self._hits: dict[tuple[str, str], deque[float]] = {}
        self._lock = threading.Lock()

    def check(self, bucket: str, client: str, limit: int, window_seconds: float = 60.0) -> float:
        """Record a hit; return 0 if allowed, else seconds until a slot frees up."""
        if limit <= 0:
            return 0.0
        now = self._clock()
        key = (bucket, client)
        with self._lock:
            hits = self._hits.get(key)
            if hits is None:
                if len(self._hits) >= MAX_TRACKED_CLIENTS:
                    self._evict(now, window_seconds)
                hits = self._hits[key] = deque()
            while hits and now - hits[0] >= window_seconds:
                hits.popleft()
            if len(hits) >= limit:
                return max(0.0, window_seconds - (now - hits[0]))
            hits.append(now)
            return 0.0

    def _evict(self, now: float, window_seconds: float) -> None:
        stale = [k for k, v in self._hits.items() if not v or now - v[-1] >= window_seconds]
        for key in stale:
            del self._hits[key]
        if len(self._hits) >= MAX_TRACKED_CLIENTS:  # still full: drop the oldest half
            for key in list(self._hits)[: MAX_TRACKED_CLIENTS // 2]:
                del self._hits[key]

    def reset(self) -> None:
        with self._lock:
            self._hits.clear()


def rate_limit(bucket: str) -> Callable[[Request], None]:
    """FastAPI dependency enforcing the configured per-minute limit for ``bucket``."""

    def dependency(request: Request) -> None:
        settings = request.app.state.settings
        limit = int(getattr(settings, f"rate_limit_{bucket}_per_minute"))
        limiter: RateLimiter = request.app.state.rate_limiter
        client = request.client.host if request.client else "unknown"
        retry_after = limiter.check(bucket, client, limit)
        if retry_after:
            raise AppError(
                f"Rate limit exceeded for {bucket} requests; retry in {int(retry_after) + 1}s.",
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                code="rate_limited",
            )

    return dependency
