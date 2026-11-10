import logging
import threading
import time
from dataclasses import dataclass

from fastapi import Request
from redis import Redis

from app.core.config import get_settings

logger = logging.getLogger("sentinelgraph.rate_limit")


@dataclass(frozen=True)
class RateLimitResult:
    allowed: bool
    limit: int
    remaining: int
    reset_epoch: int
    retry_after_seconds: int


class _FixedWindowRateLimiter:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._buckets: dict[str, tuple[int, int]] = {}  # key -> (window_id, count)

    def reset(self) -> None:
        with self._lock:
            self._buckets.clear()

    def _increment_memory(self, key: str, window_id: int) -> int:
        with self._lock:
            stale = [k for k, (w, _) in self._buckets.items() if w < window_id - 1]
            for k in stale:
                del self._buckets[k]
            cur_w, cur_count = self._buckets.get(key, (window_id, 0))
            if cur_w != window_id:
                cur_count = 0
            cur_count += 1
            self._buckets[key] = (window_id, cur_count)
            return cur_count

    def check(self, client_ip: str, bucket: str, limit: int) -> RateLimitResult:
        now = time.time()
        window_id = int(now // 60)
        reset_epoch = (window_id + 1) * 60
        retry_after = max(1, int(reset_epoch - now))
        redis_key = f"sg:rl:{bucket}:{client_ip}:{window_id}"

        settings = get_settings()
        count: int | None = None
        if settings.redis_url:
            try:
                client = Redis.from_url(settings.redis_url, socket_connect_timeout=1, socket_timeout=1)
                pipe = client.pipeline()
                pipe.incr(redis_key)
                pipe.expire(redis_key, 70)
                res = pipe.execute()
                count = int(res[0])
            except Exception:
                count = None

        if count is None:
            count = self._increment_memory(f"{bucket}:{client_ip}", window_id)

        remaining = max(0, limit - count)
        return RateLimitResult(
            allowed=count <= limit,
            limit=limit,
            remaining=remaining,
            reset_epoch=reset_epoch,
            retry_after_seconds=retry_after,
        )


_limiter = _FixedWindowRateLimiter()


def reset_rate_limiter() -> None:
    """Reset in-memory rate-limit counters (useful for isolated tests) and flush test Redis keys if any."""
    _limiter.reset()
    settings = get_settings()
    if settings.redis_url:
        try:
            client = Redis.from_url(settings.redis_url, socket_connect_timeout=1, socket_timeout=1)
            for key in client.scan_iter(match="sg:rl:*", count=500):
                client.delete(key)
        except Exception:
            pass


def classify_rate_bucket(method: str, path: str) -> tuple[str | None, int]:
    settings = get_settings()
    if path in ("/api/v1/healthz", "/api/v1/readyz"):
        return None, 0
    if path in (
        "/api/v1/auth/login",
        "/api/v1/auth/refresh",
        "/api/v1/auth/oidc/callback",
        "/api/v1/auth/change-password",
    ):
        return "auth", settings.rate_limit_auth_rpm
    if method.upper() in ("POST", "PUT", "PATCH", "DELETE"):
        return "write", settings.rate_limit_write_rpm
    return "default", settings.rate_limit_default_rpm


def extract_client_ip(request: Request) -> str:
    xff = request.headers.get("X-Forwarded-For", "").strip()
    if xff:
        return xff.split(",")[0].strip()
    if request.client and request.client.host:
        return str(request.client.host)
    return "unknown"


def check_request_rate_limit(request: Request) -> RateLimitResult | None:
    settings = get_settings()
    if not settings.rate_limit_enabled:
        return None
    bucket, limit = classify_rate_bucket(request.method, request.url.path)
    if bucket is None or limit <= 0:
        return None
    ip = extract_client_ip(request)
    return _limiter.check(ip, bucket, limit)
