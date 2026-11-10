import hashlib
import hmac
import ipaddress
import json
import logging
import secrets
import socket
import uuid
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlparse

import httpx
from sqlalchemy import desc, select
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.errors import NotFoundError, ValidationAppError
from app.core.permissions import Permission, require_permission
from app.core.security import decrypt_secret, encrypt_secret
from app.db.models import WebhookSubscription
from app.services.audit_service import record_audit_event
from app.services.context import ActorContext

logger = logging.getLogger("sentinelgraph.webhooks")

SUPPORTED_WEBHOOK_EVENTS = frozenset(
    {
        "attack_path.high_risk",
        "finding.critical",
        "import.committed",
        "test.ping",
    }
)


def _is_ip_restricted(ip_obj: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    return (
        ip_obj.is_private
        or ip_obj.is_loopback
        or ip_obj.is_link_local
        or ip_obj.is_multicast
        or ip_obj.is_reserved
        or ip_obj.is_unspecified
    )


def validate_webhook_url(target_url: str) -> str:
    settings = get_settings()
    cleaned = target_url.strip()
    parsed = urlparse(cleaned)
    if parsed.scheme not in ("http", "https"):
        raise ValidationAppError(
            code="INVALID_WEBHOOK_URL",
            message="Webhook URL must use http or https scheme.",
        )
    hostname = parsed.hostname
    if not hostname:
        raise ValidationAppError(
            code="INVALID_WEBHOOK_URL",
            message="Webhook URL missing hostname.",
        )

    if settings.webhook_allow_private_urls:
        return cleaned

    low_host = hostname.lower()
    if low_host in ("localhost", "localhost.localdomain", "metadata.google.internal"):
        raise ValidationAppError(
            code="SSRF_URL_BLOCKED",
            message=f"Webhook target hostname '{hostname}' is blocked by SSRF policy.",
        )

    # Check if host literal is an IP address
    try:
        ip_literal = ipaddress.ip_address(hostname)
        if _is_ip_restricted(ip_literal):
            raise ValidationAppError(
                code="SSRF_URL_BLOCKED",
                message=f"Webhook target IP '{hostname}' resolves to a private, loopback, or link-local address.",
            )
        return cleaned
    except ValueError:
        pass

    # DNS resolution check (best-effort against local/private metadata networks)
    try:
        addrinfos = socket.getaddrinfo(hostname, parsed.port or (443 if parsed.scheme == "https" else 80))
    except socket.gaierror:
        return cleaned

    for _, _, _, _, sockaddr in addrinfos:
        ip_str = str(sockaddr[0]).split("%")[0]
        try:
            ip_obj = ipaddress.ip_address(ip_str)
            if _is_ip_restricted(ip_obj):
                raise ValidationAppError(
                    code="SSRF_URL_BLOCKED",
                    message=f"Webhook host '{hostname}' resolved to restricted IP '{ip_str}'.",
                )
        except ValueError:
            continue
    return cleaned


def sign_webhook_payload(secret: str, payload_bytes: bytes, timestamp: int) -> str:
    signed_content = f"{timestamp}.".encode() + payload_bytes
    sig = hmac.new(secret.encode("utf-8"), signed_content, hashlib.sha256).hexdigest()
    return f"t={timestamp},v1={sig}"


def _serialize_webhook(w: WebhookSubscription) -> dict[str, Any]:
    return {
        "id": str(w.id),
        "tenant_id": str(w.tenant_id),
        "name": w.name,
        "target_url": w.target_url,
        "event_types": w.event_types,
        "enabled": w.enabled,
        "min_priority_score": w.min_priority_score,
        "has_signing_secret": bool(w.encrypted_signing_secret),
        "last_delivery_at": w.last_delivery_at.isoformat() if w.last_delivery_at else None,
        "last_status_code": w.last_status_code,
        "last_error": w.last_error,
        "created_at": w.created_at.isoformat(),
    }


def list_webhooks(db: Session, ctx: ActorContext) -> list[dict[str, Any]]:
    require_permission(ctx.role, Permission.INTEGRATION_READ)
    rows = list(
        db.execute(
            select(WebhookSubscription)
            .where(WebhookSubscription.tenant_id == ctx.tenant_id)
            .order_by(desc(WebhookSubscription.created_at))
        ).scalars()
    )
    return [_serialize_webhook(w) for w in rows]


def create_webhook(
    db: Session,
    ctx: ActorContext,
    *,
    name: str,
    target_url: str,
    event_types: list[str],
    signing_secret: str | None = None,
    min_priority_score: float = 70.0,
    enabled: bool = True,
) -> dict[str, Any]:
    require_permission(ctx.role, Permission.INTEGRATION_MANAGE)
    safe_url = validate_webhook_url(target_url)

    cleaned_events = [e.strip() for e in event_types if e.strip()]
    if not cleaned_events:
        cleaned_events = ["attack_path.high_risk"]
    for ev in cleaned_events:
        if ev not in SUPPORTED_WEBHOOK_EVENTS:
            raise ValidationAppError(
                code="INVALID_WEBHOOK_EVENT",
                message=f"Unsupported webhook event type '{ev}'.",
            )

    raw_secret = (signing_secret or "").strip() or f"sgwh_{secrets.token_urlsafe(24)}"
    sub = WebhookSubscription(
        tenant_id=ctx.tenant_id,
        name=name.strip(),
        target_url=safe_url,
        event_types=cleaned_events,
        encrypted_signing_secret=encrypt_secret(raw_secret),
        enabled=enabled,
        min_priority_score=min_priority_score,
    )
    db.add(sub)
    db.flush()

    record_audit_event(
        db,
        tenant_id=ctx.tenant_id,
        actor_user_id=ctx.user_id,
        actor_email=ctx.email,
        action="webhook.create",
        object_type="webhook_subscription",
        object_id=str(sub.id),
        outcome="success",
        request_id=ctx.request_id,
        details={"target_url": safe_url, "event_types": cleaned_events},
    )
    db.commit()
    return _serialize_webhook(sub)


def delete_webhook(db: Session, ctx: ActorContext, *, webhook_id: uuid.UUID) -> dict[str, str]:
    require_permission(ctx.role, Permission.INTEGRATION_MANAGE)
    sub = db.execute(
        select(WebhookSubscription).where(
            WebhookSubscription.id == webhook_id,
            WebhookSubscription.tenant_id == ctx.tenant_id,
        )
    ).scalar_one_or_none()
    if sub is None:
        raise NotFoundError(code="WEBHOOK_NOT_FOUND", message="Webhook subscription not found")

    sub_name = sub.name
    db.delete(sub)
    db.flush()
    record_audit_event(
        db,
        tenant_id=ctx.tenant_id,
        actor_user_id=ctx.user_id,
        actor_email=ctx.email,
        action="webhook.delete",
        object_type="webhook_subscription",
        object_id=str(webhook_id),
        outcome="success",
        request_id=ctx.request_id,
        details={"name": sub_name},
    )
    db.commit()
    return {"status": "deleted", "id": str(webhook_id)}


def _send_to_subscription(
    sub: WebhookSubscription,
    *,
    event_type: str,
    payload: dict[str, Any],
    http_transport: httpx.BaseTransport | None = None,
) -> tuple[int | None, str | None]:
    settings = get_settings()
    try:
        safe_url = validate_webhook_url(sub.target_url)
    except ValidationAppError as exc:
        sub.last_delivery_at = datetime.now(UTC)
        sub.last_status_code = None
        sub.last_error = exc.message
        return None, exc.message

    body_dict = {
        "event_id": str(uuid.uuid4()),
        "event_type": event_type,
        "tenant_id": str(sub.tenant_id),
        "timestamp": int(datetime.now(UTC).timestamp()),
        "data": payload,
    }
    body_bytes = json.dumps(body_dict, separators=(",", ":"), sort_keys=True).encode("utf-8")
    secret = decrypt_secret(sub.encrypted_signing_secret)
    ts = int(datetime.now(UTC).timestamp())
    signature = sign_webhook_payload(secret, body_bytes, ts)

    headers = {
        "Content-Type": "application/json",
        "User-Agent": "SentinelGraph-Webhook/1.0",
        "X-SentinelGraph-Event": event_type,
        "X-SentinelGraph-Signature": signature,
    }
    try:
        with httpx.Client(timeout=settings.webhook_timeout_seconds, transport=http_transport) as client:
            resp = client.post(safe_url, content=body_bytes, headers=headers)
        sub.last_delivery_at = datetime.now(UTC)
        sub.last_status_code = resp.status_code
        sub.last_error = None if resp.status_code < 400 else f"HTTP {resp.status_code}"
        return resp.status_code, sub.last_error
    except Exception as exc:
        sub.last_delivery_at = datetime.now(UTC)
        sub.last_status_code = None
        sub.last_error = str(exc)[:400]
        return None, sub.last_error


def test_webhook_delivery(
    db: Session,
    ctx: ActorContext,
    *,
    webhook_id: uuid.UUID,
    http_transport: httpx.BaseTransport | None = None,
) -> dict[str, Any]:
    require_permission(ctx.role, Permission.INTEGRATION_MANAGE)
    sub = db.execute(
        select(WebhookSubscription).where(
            WebhookSubscription.id == webhook_id,
            WebhookSubscription.tenant_id == ctx.tenant_id,
        )
    ).scalar_one_or_none()
    if sub is None:
        raise NotFoundError(code="WEBHOOK_NOT_FOUND", message="Webhook subscription not found")

    status_code, error = _send_to_subscription(
        sub,
        event_type="test.ping",
        payload={"message": "SentinelGraph test webhook notification", "subscription": sub.name},
        http_transport=http_transport,
    )
    record_audit_event(
        db,
        tenant_id=ctx.tenant_id,
        actor_user_id=ctx.user_id,
        actor_email=ctx.email,
        action="webhook.test",
        object_type="webhook_subscription",
        object_id=str(sub.id),
        outcome="success" if status_code and status_code < 400 else "failed",
        request_id=ctx.request_id,
        details={"status_code": status_code, "error": error},
    )
    db.commit()
    return {
        "webhook_id": str(sub.id),
        "delivered": bool(status_code is not None and status_code < 400),
        "status_code": status_code,
        "error": error,
    }


def dispatch_webhook_events(
    db: Session,
    ctx: ActorContext,
    *,
    event_type: str,
    payload: dict[str, Any],
    priority_score: float | None = None,
    http_transport: httpx.BaseTransport | None = None,
) -> int:
    subs = list(
        db.execute(
            select(WebhookSubscription).where(
                WebhookSubscription.tenant_id == ctx.tenant_id,
                WebhookSubscription.enabled.is_(True),
            )
        ).scalars()
    )
    delivered = 0
    for sub in subs:
        if event_type not in (sub.event_types or []):
            continue
        if priority_score is not None and priority_score < sub.min_priority_score:
            continue
        status_code, _ = _send_to_subscription(
            sub,
            event_type=event_type,
            payload=payload,
            http_transport=http_transport,
        )
        if status_code is not None and status_code < 400:
            delivered += 1
    if subs:
        db.commit()
    return delivered
