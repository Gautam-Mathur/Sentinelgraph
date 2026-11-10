import hashlib
import hmac
import logging
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Protocol
from urllib.parse import quote, urlparse

import httpx

from app.core.config import get_settings
from app.core.errors import AppError

logger = logging.getLogger("sentinelgraph.storage")


class StagingStorage(Protocol):
    def put_bytes(self, object_key: str, content: bytes) -> str: ...

    def get_bytes(self, object_key: str) -> bytes: ...

    def delete_object(self, object_key: str) -> None: ...


class LocalStagingStorage:
    """Local filesystem staging storage with path traversal guards."""

    def __init__(self, base_dir: str | Path) -> None:
        self.base_dir = Path(base_dir).resolve()
        self.base_dir.mkdir(parents=True, exist_ok=True)

    def _resolve_safe_path(self, object_key: str) -> Path:
        clean_key = object_key.lstrip("/")
        candidate = (self.base_dir / clean_key).resolve()
        if candidate != self.base_dir and not candidate.is_relative_to(self.base_dir):
            raise AppError(
                code="INVALID_STORAGE_KEY",
                message="Invalid staging storage key",
                status_code=400,
            )
        return candidate

    def put_bytes(self, object_key: str, content: bytes) -> str:
        target = self._resolve_safe_path(object_key)
        target.parent.mkdir(parents=True, exist_ok=True)
        tmp = target.with_name(f".{target.name}.{uuid.uuid4().hex}.tmp")
        tmp.write_bytes(content)
        tmp.replace(target)
        return str(target)

    def get_bytes(self, object_key: str) -> bytes:
        target = self._resolve_safe_path(object_key)
        if not target.exists():
            raise AppError(
                code="STAGED_FILE_MISSING",
                message="Staged import payload could not be found in storage.",
                status_code=404,
            )
        return target.read_bytes()

    def delete_object(self, object_key: str) -> None:
        target = self._resolve_safe_path(object_key)
        if target.exists() and target.is_file():
            target.unlink()


class S3StagingStorage:
    """Pure-Python AWS SigV4 HTTP client for S3 / MinIO compatible staging buckets."""

    def __init__(
        self,
        *,
        endpoint_url: str,
        bucket: str,
        region: str,
        access_key: str,
        secret_key: str,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        self.endpoint_url = endpoint_url.rstrip("/")
        self.bucket = bucket
        self.region = region
        self.access_key = access_key
        self.secret_key = secret_key
        self.transport = transport

    def _sign_headers(self, method: str, url: str, payload: bytes) -> dict[str, str]:
        parsed = urlparse(url)
        now = datetime.now(UTC)
        amz_date = now.strftime("%Y%m%dT%H%M%SZ")
        date_stamp = now.strftime("%Y%m%d")
        payload_hash = hashlib.sha256(payload).hexdigest()

        canonical_uri = quote(parsed.path or "/", safe="/~-._")
        canonical_headers = (
            f"host:{parsed.netloc}\n"
            f"x-amz-content-sha256:{payload_hash}\n"
            f"x-amz-date:{amz_date}\n"
        )
        signed_headers = "host;x-amz-content-sha256;x-amz-date"
        canonical_request = "\n".join(
            [
                method.upper(),
                canonical_uri,
                parsed.query,
                canonical_headers,
                signed_headers,
                payload_hash,
            ]
        )

        scope = f"{date_stamp}/{self.region}/s3/aws4_request"
        string_to_sign = "\n".join(
            [
                "AWS4-HMAC-SHA256",
                amz_date,
                scope,
                hashlib.sha256(canonical_request.encode("utf-8")).hexdigest(),
            ]
        )

        def _hmac(key: bytes, msg: str) -> bytes:
            return hmac.new(key, msg.encode("utf-8"), hashlib.sha256).digest()

        k_date = _hmac(f"AWS4{self.secret_key}".encode(), date_stamp)
        k_region = _hmac(k_date, self.region)
        k_service = _hmac(k_region, "s3")
        k_signing = _hmac(k_service, "aws4_request")
        signature = hmac.new(k_signing, string_to_sign.encode("utf-8"), hashlib.sha256).hexdigest()

        authorization = (
            f"AWS4-HMAC-SHA256 Credential={self.access_key}/{scope}, "
            f"SignedHeaders={signed_headers}, Signature={signature}"
        )
        return {
            "Host": parsed.netloc,
            "x-amz-date": amz_date,
            "x-amz-content-sha256": payload_hash,
            "Authorization": authorization,
        }

    def _object_url(self, object_key: str) -> str:
        clean_key = object_key.lstrip("/")
        return f"{self.endpoint_url}/{self.bucket}/{clean_key}"

    def put_bytes(self, object_key: str, content: bytes) -> str:
        url = self._object_url(object_key)
        headers = self._sign_headers("PUT", url, content)
        headers["Content-Type"] = "application/octet-stream"
        with httpx.Client(timeout=15.0, transport=self.transport) as client:
            resp = client.put(url, content=content, headers=headers)
            if resp.status_code >= 400:
                raise AppError(
                    code="OBJECT_STORAGE_ERROR",
                    message=f"S3 upload failed with HTTP {resp.status_code}",
                    status_code=502,
                )
        return f"s3://{self.bucket}/{object_key.lstrip('/')}"

    def get_bytes(self, object_key: str) -> bytes:
        url = self._object_url(object_key)
        headers = self._sign_headers("GET", url, b"")
        with httpx.Client(timeout=15.0, transport=self.transport) as client:
            resp = client.get(url, headers=headers)
            if resp.status_code == 404:
                raise AppError(
                    code="STAGED_FILE_MISSING",
                    message="Staged import payload missing from S3 object storage.",
                    status_code=404,
                )
            if resp.status_code >= 400:
                raise AppError(
                    code="OBJECT_STORAGE_ERROR",
                    message=f"S3 fetch failed with HTTP {resp.status_code}",
                    status_code=502,
                )
            return resp.content

    def delete_object(self, object_key: str) -> None:
        url = self._object_url(object_key)
        headers = self._sign_headers("DELETE", url, b"")
        with httpx.Client(timeout=15.0, transport=self.transport) as client:
            resp = client.delete(url, headers=headers)
            if resp.status_code >= 400 and resp.status_code != 404:
                logger.warning("S3 delete failed key=%s status=%s", object_key, resp.status_code)


def get_staging_storage() -> StagingStorage:
    settings = get_settings()
    if settings.object_storage_backend.lower() == "s3":
        if not settings.object_storage_endpoint_url or not settings.object_storage_access_key:
            raise AppError(
                code="OBJECT_STORAGE_MISCONFIGURED",
                message="S3 object storage backend selected without endpoint URL or access key.",
                status_code=500,
            )
        return S3StagingStorage(
            endpoint_url=settings.object_storage_endpoint_url,
            bucket=settings.object_storage_bucket,
            region=settings.object_storage_region,
            access_key=settings.object_storage_access_key,
            secret_key=settings.object_storage_secret_key,
        )
    return LocalStagingStorage(settings.import_temp_dir)
