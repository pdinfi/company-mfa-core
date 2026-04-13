"""Simple rate limiting with memory and optional Redis backends."""

from __future__ import annotations

import time
from dataclasses import dataclass
from threading import Lock
from typing import Optional

from django_mfa_core.settings import get_mfa_settings


@dataclass
class RateLimitResult:
    """Outcome of a rate-limit check."""

    allowed: bool
    retry_after: Optional[float] = None


class BaseRateLimiter:
    """Protocol-like base class for limiters."""

    def hit(self, key: str, limit: int, window_seconds: int) -> RateLimitResult:
        raise NotImplementedError


class MemoryRateLimiter(BaseRateLimiter):
    """Thread-safe fixed window counter in process memory."""

    def __init__(self) -> None:
        self._lock = Lock()
        self._windows: dict[str, tuple[float, int]] = {}

    def hit(self, key: str, limit: int, window_seconds: int) -> RateLimitResult:
        now = time.time()
        with self._lock:
            window_start, count = self._windows.get(key, (now, 0))
            if now - window_start >= window_seconds:
                window_start = now
                count = 0
            count += 1
            self._windows[key] = (window_start, count)
            if count > limit:
                retry = window_seconds - (now - window_start)
                return RateLimitResult(allowed=False, retry_after=max(retry, 0.0))
            return RateLimitResult(allowed=True)


class RedisRateLimiter(BaseRateLimiter):
    """Redis-backed fixed window using INCR + EXPIRE."""

    def __init__(self, url: str) -> None:
        from redis import Redis

        self._client = Redis.from_url(url)

    def hit(self, key: str, limit: int, window_seconds: int) -> RateLimitResult:
        pipe = self._client.pipeline(True)
        pipe.incr(key)
        pipe.ttl(key)
        count, ttl = pipe.execute()
        if ttl == -1:
            self._client.expire(key, window_seconds)
            ttl = window_seconds
        if int(count) > limit:
            return RateLimitResult(allowed=False, retry_after=float(ttl))
        return RateLimitResult(allowed=True)


_limiter_singleton: Optional[BaseRateLimiter] = None


def _parse_rule(rule: str) -> tuple[int, int]:
    """Parse rules like '5/m' into (limit, window_seconds)."""
    amount_part, unit = rule.strip().split("/", 1)
    limit = int(amount_part)
    unit = unit.lower()
    if unit == "s":
        window = 1
    elif unit == "m":
        window = 60
    elif unit == "h":
        window = 3600
    else:  # pragma: no cover - validated by config
        raise ValueError(f"Unsupported rate limit unit: {unit}")
    return limit, window


def get_rate_limiter() -> BaseRateLimiter:
    """Return a process-wide rate limiter based on MFA_SETTINGS."""
    global _limiter_singleton
    if _limiter_singleton is not None:
        return _limiter_singleton
    cfg = get_mfa_settings()
    backend = cfg.get("RATE_LIMIT_BACKEND", "memory")
    if backend == "redis":
        url = cfg.get("REDIS_URL")
        if not url:
            raise RuntimeError("REDIS_URL required for redis rate limiter")
        _limiter_singleton = RedisRateLimiter(url)
    else:
        _limiter_singleton = MemoryRateLimiter()
    return _limiter_singleton


def rate_limit(key: str, rule: str) -> RateLimitResult:
    """Apply a rule such as '5/m' to a namespaced key."""
    limit, window = _parse_rule(rule)
    return get_rate_limiter().hit(key, limit, window)
