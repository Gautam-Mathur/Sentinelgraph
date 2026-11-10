from functools import lru_cache
from typing import Literal

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False,
    )

    app_env: Literal["development", "test", "local", "staging", "production"] = "development"
    app_name: str = "SentinelGraph"
    app_version: str = "1.0.0"

    database_url: str = (
        "postgresql+psycopg://sentinelgraph_app:sentinelgraph_dev_pw@localhost:5432/sentinelgraph"
    )
    database_admin_url: str = (
        "postgresql+psycopg://postgres:postgres_dev_pw@localhost:5432/sentinelgraph"
    )
    redis_url: str = "redis://localhost:6379/0"
    worker_inline_fallback: bool = False

    secret_key: str = Field(
        default="dev-only-change-in-production-32-bytes-minimum-key",
        min_length=32,
    )
    # Comma-separated Fernet keys for key rotation (newest first)
    encryption_master_key: str = "xV7mX5n2hH3lF9wQ1bZ4yR8pK6jD0vN2cT7gU9sM1aA="
    jwt_algorithm: str = "HS256"
    access_token_expire_minutes: int = 480

    oidc_issuer_url: str = ""
    oidc_client_id: str = ""
    oidc_client_secret: str = ""
    oidc_redirect_uri: str = "http://localhost:5173/auth/callback"
    oidc_scopes: str = "openid email profile"
    oidc_jit_tenant_slug: str = ""
    oidc_jit_role: str = "read_only"

    refresh_token_expire_days: int = 7

    rate_limit_enabled: bool = True
    rate_limit_auth_rpm: int = 60
    rate_limit_write_rpm: int = 300
    rate_limit_default_rpm: int = 1200

    object_storage_backend: Literal["local", "s3"] = "local"
    object_storage_bucket: str = "sentinelgraph-local-staging"
    object_storage_endpoint_url: str = ""
    object_storage_region: str = "us-east-1"
    object_storage_access_key: str = ""
    object_storage_secret_key: str = ""
    import_temp_dir: str = "/tmp/sentinelgraph-uploads"
    max_import_bytes: int = 10 * 1024 * 1024  # 10 MiB
    parser_timeout_seconds: float = 10.0

    webhook_timeout_seconds: float = 5.0
    webhook_allow_private_urls: bool = False

    log_level: str = "INFO"
    otel_service_name: str = "sentinelgraph-api"
    otel_exporter_otlp_endpoint: str = ""
    allowed_origins: str = "http://localhost:5173,http://127.0.0.1:5173"

    # Graph / Path Engine Bounds
    default_max_hops: int = 6
    hard_max_hops: int = 12
    default_max_candidates: int = 200
    hard_max_candidates: int = 2000
    path_search_timeout_seconds: float = 5.0

    @field_validator("secret_key")
    @classmethod
    def validate_prod_secret(cls, v: str, info: object) -> str:
        # Enforce non-default secret in production
        data = getattr(info, "data", {})
        if data.get("app_env") == "production" and "dev-only" in v:
            raise ValueError("Production SECRET_KEY must not use the development placeholder.")
        return v

    @property
    def cors_origins(self) -> list[str]:
        return [origin.strip() for origin in self.allowed_origins.split(",") if origin.strip()]

    @property
    def local_dev_auth_enabled(self) -> bool:
        return self.app_env in ("development", "test", "local")


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()
