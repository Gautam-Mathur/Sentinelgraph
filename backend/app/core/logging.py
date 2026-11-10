import contextvars
import json
import logging
import re
from datetime import UTC, datetime
from typing import Any

correlation_id_var: contextvars.ContextVar[str] = contextvars.ContextVar(
    "correlation_id", default="-"
)
tenant_id_var: contextvars.ContextVar[str] = contextvars.ContextVar("tenant_id", default="-")

SENSITIVE_KEYS = frozenset(
    {
        "password",
        "password_hash",
        "secret",
        "secret_key",
        "token",
        "access_token",
        "refresh_token",
        "id_token",
        "authorization",
        "cookie",
        "api_key",
        "private_key",
        "client_secret",
        "ntlm_hash",
        "krbtgt",
        "raw_xml",
        "encrypted_secret_ref",
    }
)

BEARER_PATTERN = re.compile(r"Bearer\s+[A-Za-z0-9\-._~+/]+=*", re.IGNORECASE)


def redact_value(key: str, value: Any) -> Any:
    lowered = key.lower()
    if lowered in SENSITIVE_KEYS or any(
        tok in lowered for tok in ("password", "secret", "token", "private_key", "credential")
    ):
        return "[REDACTED]"
    if isinstance(value, str):
        return BEARER_PATTERN.sub("Bearer [REDACTED]", value)
    if isinstance(value, dict):
        return redact_dict(value)
    if isinstance(value, list):
        return [redact_value(key, item) for item in value]
    return value


def redact_dict(data: dict[str, Any]) -> dict[str, Any]:
    return {k: redact_value(k, v) for k, v in data.items()}


class StructuredJsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "timestamp": datetime.now(UTC).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": BEARER_PATTERN.sub("Bearer [REDACTED]", record.getMessage()),
            "request_id": correlation_id_var.get("-"),
            "tenant_id": tenant_id_var.get("-"),
        }
        extra_fields = getattr(record, "extra_fields", None)
        if isinstance(extra_fields, dict):
            payload["context"] = redact_dict(extra_fields)
        if record.exc_info and record.exc_info[0] is not None:
            payload["exception"] = self.formatException(record.exc_info)
        return json.dumps(payload, default=str)


def configure_logging(level: str = "INFO") -> None:
    root = logging.getLogger()
    root.setLevel(getattr(logging, level.upper(), logging.INFO))
    handler = logging.StreamHandler()
    handler.setFormatter(StructuredJsonFormatter())
    root.handlers = [handler]
