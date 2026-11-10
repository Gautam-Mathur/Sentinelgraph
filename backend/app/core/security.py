import base64
import hashlib
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

import jwt
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from cryptography.fernet import Fernet, InvalidToken, MultiFernet

from app.core.config import get_settings
from app.core.errors import AuthenticationError, ValidationAppError

_ph = PasswordHasher()


def validate_password_strength(password: str) -> None:
    if len(password) < 12:
        raise ValidationAppError(
            code="WEAK_PASSWORD",
            message="Password must be at least 12 characters long and include uppercase, lowercase, digit, and special character.",
        )
    has_upper = any(ch.isupper() for ch in password)
    has_lower = any(ch.islower() for ch in password)
    has_digit = any(ch.isdigit() for ch in password)
    has_symbol = any(not ch.isalnum() for ch in password)
    if not (has_upper and has_lower and has_digit and has_symbol):
        raise ValidationAppError(
            code="WEAK_PASSWORD",
            message="Password must include at least one uppercase letter, lowercase letter, digit, and special character.",
        )


def hash_password(password: str) -> str:
    return _ph.hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    try:
        return _ph.verify(password_hash, password)
    except VerifyMismatchError:
        return False


def _normalize_fernet_key(raw_key: str) -> bytes:
    cleaned = raw_key.strip().encode("utf-8")
    try:
        Fernet(cleaned)
        return cleaned
    except Exception:
        digest = hashlib.sha256(cleaned).digest()
        return base64.urlsafe_b64encode(digest)


def _get_multi_fernet() -> MultiFernet:
    settings = get_settings()
    keys = [
        _normalize_fernet_key(k)
        for k in settings.encryption_master_key.split(",")
        if k.strip()
    ]
    if not keys:
        keys = [_normalize_fernet_key(settings.secret_key)]
    return MultiFernet([Fernet(k) for k in keys])


def encrypt_secret(plaintext: str) -> str:
    return _get_multi_fernet().encrypt(plaintext.encode("utf-8")).decode("utf-8")


def decrypt_secret(ciphertext: str) -> str:
    try:
        return _get_multi_fernet().decrypt(ciphertext.encode("utf-8")).decode("utf-8")
    except InvalidToken as exc:
        raise AuthenticationError("Unable to decrypt stored connector secret", "SECRET_DECRYPT_ERROR") from exc


def rotate_secret(ciphertext: str) -> str:
    return _get_multi_fernet().rotate(ciphertext.encode("utf-8")).decode("utf-8")


def create_access_token(
    *,
    user_id: uuid.UUID,
    email: str,
    tenant_id: uuid.UUID,
    role: str,
    auth_method: str = "local_dev",
    expires_delta: timedelta | None = None,
) -> str:
    settings = get_settings()
    now = datetime.now(UTC)
    expire = now + (expires_delta or timedelta(minutes=settings.access_token_expire_minutes))
    payload: dict[str, Any] = {
        "sub": str(user_id),
        "email": email,
        "tenant_id": str(tenant_id),
        "role": role,
        "auth_method": auth_method,
        "token_use": "access",
        "jti": str(uuid.uuid4()),
        "iat": int(now.timestamp()),
        "exp": int(expire.timestamp()),
    }
    return str(jwt.encode(payload, settings.secret_key, algorithm=settings.jwt_algorithm))


def create_refresh_token(
    *,
    user_id: uuid.UUID,
    email: str,
    tenant_id: uuid.UUID,
    role: str,
    auth_method: str = "local_dev",
    expires_delta: timedelta | None = None,
) -> str:
    settings = get_settings()
    now = datetime.now(UTC)
    expire = now + (expires_delta or timedelta(days=settings.refresh_token_expire_days))
    payload: dict[str, Any] = {
        "sub": str(user_id),
        "email": email,
        "tenant_id": str(tenant_id),
        "role": role,
        "auth_method": auth_method,
        "token_use": "refresh",
        "jti": str(uuid.uuid4()),
        "iat": int(now.timestamp()),
        "exp": int(expire.timestamp()),
    }
    return str(jwt.encode(payload, settings.secret_key, algorithm=settings.jwt_algorithm))


def decode_access_token(token: str) -> dict[str, Any]:
    settings = get_settings()
    try:
        payload = jwt.decode(
            token,
            settings.secret_key,
            algorithms=[settings.jwt_algorithm],
            options={"require": ["sub", "tenant_id", "role", "exp"]},
        )
        if payload.get("token_use") == "refresh":
            raise AuthenticationError("Refresh token cannot be used as access token", "TOKEN_INVALID")
        return dict(payload)
    except jwt.ExpiredSignatureError as exc:
        raise AuthenticationError("Access token expired", "TOKEN_EXPIRED") from exc
    except AuthenticationError:
        raise
    except jwt.InvalidTokenError as exc:
        raise AuthenticationError("Invalid access token", "TOKEN_INVALID") from exc


def decode_refresh_token(token: str) -> dict[str, Any]:
    settings = get_settings()
    try:
        payload = jwt.decode(
            token,
            settings.secret_key,
            algorithms=[settings.jwt_algorithm],
            options={"require": ["sub", "tenant_id", "role", "jti", "exp"]},
        )
        if payload.get("token_use") != "refresh":
            raise AuthenticationError("Invalid refresh token", "REFRESH_TOKEN_INVALID")
        return dict(payload)
    except jwt.ExpiredSignatureError as exc:
        raise AuthenticationError("Refresh token expired", "REFRESH_TOKEN_EXPIRED") from exc
    except AuthenticationError:
        raise
    except jwt.InvalidTokenError as exc:
        raise AuthenticationError("Invalid refresh token", "REFRESH_TOKEN_INVALID") from exc
