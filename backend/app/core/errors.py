from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class FieldError(BaseModel):
    model_config = ConfigDict(extra="forbid")

    field: str
    message: str
    code: str = "validation_error"


class ErrorEnvelope(BaseModel):
    model_config = ConfigDict(extra="forbid")

    code: str
    message: str
    request_id: str
    field_errors: list[FieldError] = Field(default_factory=list)


class AppError(Exception):
    def __init__(
        self,
        code: str,
        message: str,
        status_code: int = 400,
        field_errors: list[FieldError] | None = None,
        details: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.status_code = status_code
        self.field_errors = field_errors or []
        self.details = details or {}


class AuthenticationError(AppError):
    def __init__(self, message: str = "Authentication required", code: str = "AUTH_REQUIRED") -> None:
        super().__init__(code=code, message=message, status_code=401)


class AuthorizationError(AppError):
    def __init__(self, message: str = "Insufficient permissions", code: str = "FORBIDDEN") -> None:
        super().__init__(code=code, message=message, status_code=403)


class NotFoundError(AppError):
    def __init__(self, code: str = "NOT_FOUND", message: str = "Resource not found") -> None:
        super().__init__(code=code, message=message, status_code=404)


class ConflictError(AppError):
    def __init__(self, code: str = "CONFLICT", message: str = "Resource conflict") -> None:
        super().__init__(code=code, message=message, status_code=409)


class ValidationAppError(AppError):
    def __init__(
        self,
        code: str = "VALIDATION_ERROR",
        message: str = "Invalid request input",
        field_errors: list[FieldError] | None = None,
    ) -> None:
        super().__init__(code=code, message=message, status_code=422, field_errors=field_errors)


class PayloadTooLargeError(AppError):
    def __init__(self, message: str = "Uploaded payload exceeds size limit") -> None:
        super().__init__(code="PAYLOAD_TOO_LARGE", message=message, status_code=413)
