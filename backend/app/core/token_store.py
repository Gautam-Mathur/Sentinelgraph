import logging
import threading
import uuid
from datetime import UTC, datetime

from redis import Redis
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.db.models import RevokedToken

logger = logging.getLogger("sentinelgraph.security")

_memory_lock = threading.Lock()
_memory_revoked_jtis: dict[str, float] = {}


def reset_memory_revocation_cache() -> None:
    """Test helper to clear the local in-memory revocation cache."""
    with _memory_lock:
        _memory_revoked_jtis.clear()


def _prune_memory_cache(now_ts: float) -> None:
    expired = [k for k, exp_ts in _memory_revoked_jtis.items() if exp_ts <= now_ts]
    for k in expired:
        del _memory_revoked_jtis[k]


def _get_redis() -> Redis | None:
    settings = get_settings()
    if not settings.redis_url:
        return None
    try:
        client = Redis.from_url(settings.redis_url, socket_connect_timeout=1, socket_timeout=1)
        client.ping()
        return client
    except Exception:
        return None


def revoke_token(
    db: Session,
    *,
    jti: str,
    user_id: uuid.UUID,
    token_type: str,
    expires_at: datetime,
) -> None:
    """Persist token revocation in PostgreSQL and replicate to Redis + process memory."""
    clean_jti = jti.strip()
    if not clean_jti:
        return

    existing = db.get(RevokedToken, clean_jti)
    if existing is None:
        db.add(
            RevokedToken(
                jti=clean_jti,
                user_id=user_id,
                token_type=token_type,
                expires_at=expires_at,
            )
        )
        db.flush()

    now_ts = datetime.now(UTC).timestamp()
    exp_ts = expires_at.timestamp() if expires_at.tzinfo else expires_at.replace(tzinfo=UTC).timestamp()
    ttl = max(60, int(exp_ts - now_ts))

    with _memory_lock:
        _prune_memory_cache(now_ts)
        _memory_revoked_jtis[clean_jti] = max(exp_ts, now_ts + 60.0)

    client = _get_redis()
    if client is not None:
        try:
            client.set(f"sg:revoked:{clean_jti}", token_type, ex=ttl)
        except Exception:
            logger.debug("Redis revocation cache write skipped for jti=%s", clean_jti)


def is_token_revoked(db: Session, jti: str | None) -> bool:
    if not jti:
        return False
    clean_jti = jti.strip()
    if not clean_jti:
        return False

    now_ts = datetime.now(UTC).timestamp()
    with _memory_lock:
        exp_ts = _memory_revoked_jtis.get(clean_jti)
        if exp_ts is not None:
            if exp_ts > now_ts:
                return True
            del _memory_revoked_jtis[clean_jti]

    client = _get_redis()
    if client is not None:
        try:
            if client.exists(f"sg:revoked:{clean_jti}"):
                with _memory_lock:
                    _memory_revoked_jtis[clean_jti] = now_ts + 300.0
                return True
        except Exception:
            pass

    row = db.get(RevokedToken, clean_jti)
    if row is not None:
        exp_val = row.expires_at.timestamp() if row.expires_at.tzinfo else row.expires_at.replace(tzinfo=UTC).timestamp()
        with _memory_lock:
            _memory_revoked_jtis[clean_jti] = max(exp_val, now_ts + 60.0)
        return True
    return False
