import logging
import time
import uuid

from fastapi import FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.api.v1.router import api_v1_router
from app.core.config import get_settings
from app.core.errors import AppError, ErrorEnvelope, FieldError
from app.core.logging import configure_logging, correlation_id_var, tenant_id_var
from app.core.rate_limit import check_request_rate_limit
from app.core.telemetry import metrics, tracer

settings = get_settings()
configure_logging(settings.log_level)
logger = logging.getLogger("sentinelgraph.api")


def create_app() -> FastAPI:
    application = FastAPI(
        title="SentinelGraph API",
        version=settings.app_version,
        description=(
            "Authorised, evidence-driven enterprise attack-path analysis and "
            "remediation prioritisation platform."
        ),
        docs_url="/api/v1/docs",
        openapi_url="/api/v1/openapi.json",
    )

    application.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins,
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
        allow_headers=["Authorization", "Content-Type", "X-Tenant-ID", "X-Request-ID", "Idempotency-Key"],
    )

    @application.middleware("http")
    async def correlation_and_telemetry_middleware(request: Request, call_next: object) -> JSONResponse:
        req_id = request.headers.get("X-Request-ID") or str(uuid.uuid4())
        request.state.request_id = req_id
        token_cid = correlation_id_var.set(req_id)
        token_tid = tenant_id_var.set("-")
        t0 = time.perf_counter()

        try:
            rl = check_request_rate_limit(request)
            if rl is not None and not rl.allowed:
                metrics.inc("rate_limit_blocked_total")
                envelope = ErrorEnvelope(
                    code="RATE_LIMITED",
                    message="Rate limit exceeded. Retry after cooldown window.",
                    request_id=req_id,
                    field_errors=[],
                )
                return JSONResponse(
                    status_code=429,
                    content=envelope.model_dump(),
                    headers={
                        "Retry-After": str(rl.retry_after_seconds),
                        "X-RateLimit-Limit": str(rl.limit),
                        "X-RateLimit-Remaining": "0",
                        "X-RateLimit-Reset": str(rl.reset_epoch),
                        "X-Request-ID": req_id,
                        "X-Content-Type-Options": "nosniff",
                        "X-Frame-Options": "DENY",
                    },
                )

            with tracer.start_as_current_span(f"{request.method} {request.url.path}") as span:
                span.set_attribute("http.method", request.method)
                span.set_attribute("http.route", request.url.path)
                span.set_attribute("sentinelgraph.request_id", req_id)
                response = await call_next(request)  # type: ignore[operator]
                elapsed_ms = round((time.perf_counter() - t0) * 1000.0, 2)
                metrics.observe_ms("api_request_ms", elapsed_ms)
                metrics.inc("api_requests_total")
                response.headers["X-Request-ID"] = req_id
                response.headers["X-Content-Type-Options"] = "nosniff"
                response.headers["X-Frame-Options"] = "DENY"
                if rl is not None:
                    response.headers["X-RateLimit-Limit"] = str(rl.limit)
                    response.headers["X-RateLimit-Remaining"] = str(rl.remaining)
                    response.headers["X-RateLimit-Reset"] = str(rl.reset_epoch)
                if hasattr(request.state, "tenant_id"):
                    tenant_id_var.set(str(request.state.tenant_id))
                logger.info(
                    "HTTP request completed",
                    extra={
                        "extra_fields": {
                            "method": request.method,
                            "path": request.url.path,
                            "status_code": response.status_code,
                            "duration_ms": elapsed_ms,
                        }
                    },
                )
                return response
        finally:
            correlation_id_var.reset(token_cid)
            tenant_id_var.reset(token_tid)

    @application.exception_handler(AppError)
    async def app_error_handler(request: Request, exc: AppError) -> JSONResponse:
        req_id = str(getattr(request.state, "request_id", "-"))
        envelope = ErrorEnvelope(
            code=exc.code,
            message=exc.message,
            request_id=req_id,
            field_errors=exc.field_errors,
        )
        return JSONResponse(status_code=exc.status_code, content=envelope.model_dump())

    @application.exception_handler(RequestValidationError)
    async def validation_error_handler(
        request: Request, exc: RequestValidationError
    ) -> JSONResponse:
        req_id = str(getattr(request.state, "request_id", "-"))
        field_errors = [
            FieldError(
                field=".".join(str(loc) for loc in err.get("loc", [])),
                message=str(err.get("msg", "Invalid field")),
                code=str(err.get("type", "validation_error")),
            )
            for err in exc.errors()[:15]
        ]
        envelope = ErrorEnvelope(
            code="VALIDATION_ERROR",
            message="Request validation failed.",
            request_id=req_id,
            field_errors=field_errors,
        )
        return JSONResponse(status_code=422, content=envelope.model_dump())

    @application.exception_handler(HTTPException)
    async def http_error_handler(request: Request, exc: HTTPException) -> JSONResponse:
        req_id = str(getattr(request.state, "request_id", "-"))
        envelope = ErrorEnvelope(
            code=f"HTTP_{exc.status_code}",
            message=str(exc.detail),
            request_id=req_id,
            field_errors=[],
        )
        return JSONResponse(status_code=exc.status_code, content=envelope.model_dump())

    @application.exception_handler(Exception)
    async def unhandled_error_handler(request: Request, exc: Exception) -> JSONResponse:
        req_id = str(getattr(request.state, "request_id", "-"))
        logger.exception("Unhandled server exception", exc_info=exc)
        envelope = ErrorEnvelope(
            code="INTERNAL_SERVER_ERROR",
            message="An internal error occurred. Inspect logs using request_id.",
            request_id=req_id,
            field_errors=[],
        )
        return JSONResponse(status_code=500, content=envelope.model_dump())

    application.include_router(api_v1_router)
    return application


app = create_app()
