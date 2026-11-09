"""
Custom exception classes and FastAPI exception handlers.

Provides domain-specific exceptions that map cleanly to HTTP status codes,
plus a global handler that formats errors to match the frontend's ApiError interface:
    { message: string, code: string, status: number, details?: Record<string, string[]> }
"""

from typing import Any

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse


# ── Domain Exceptions ────────────────────────────────────────────


class AppException(Exception):
    """Base exception for all application-specific errors."""

    def __init__(
        self,
        message: str,
        code: str = "APP_ERROR",
        status_code: int = 500,
        details: dict[str, list[str]] | None = None,
    ) -> None:
        self.message = message
        self.code = code
        self.status_code = status_code
        self.details = details
        super().__init__(message)


class NotFoundException(AppException):
    """Resource not found (404)."""

    def __init__(
        self,
        message: str = "Resource not found",
        details: dict[str, list[str]] | None = None,
    ) -> None:
        super().__init__(message=message, code="NOT_FOUND", status_code=404, details=details)


class UnauthorizedException(AppException):
    """Authentication required or invalid credentials (401)."""

    def __init__(
        self,
        message: str = "Not authenticated",
        details: dict[str, list[str]] | None = None,
    ) -> None:
        super().__init__(message=message, code="UNAUTHORIZED", status_code=401, details=details)


class ForbiddenException(AppException):
    """Insufficient permissions (403)."""

    def __init__(
        self,
        message: str = "Insufficient permissions",
        details: dict[str, list[str]] | None = None,
    ) -> None:
        super().__init__(message=message, code="FORBIDDEN", status_code=403, details=details)


class ConflictException(AppException):
    """Resource conflict, e.g. duplicate email (409)."""

    def __init__(
        self,
        message: str = "Resource conflict",
        details: dict[str, list[str]] | None = None,
    ) -> None:
        super().__init__(message=message, code="CONFLICT", status_code=409, details=details)


class ValidationException(AppException):
    """Business validation failure (422)."""

    def __init__(
        self,
        message: str = "Validation failed",
        details: dict[str, list[str]] | None = None,
    ) -> None:
        super().__init__(
            message=message, code="VALIDATION_ERROR", status_code=422, details=details
        )


class BadRequestException(AppException):
    """Bad request error (400)."""

    def __init__(
        self,
        message: str = "Bad request",
        details: dict[str, list[str]] | None = None,
    ) -> None:
        super().__init__(
            message=message, code="BAD_REQUEST", status_code=400, details=details
        )


# ── Exception Handlers ───────────────────────────────────────────


def _build_error_body(
    message: str,
    code: str,
    status: int,
    details: dict[str, list[str]] | None = None,
) -> dict[str, Any]:
    """Build an error response body matching the frontend's ApiError interface."""
    body: dict[str, Any] = {
        "message": message,
        "code": code,
        "status": status,
    }
    if details:
        body["details"] = details
    return body


async def _app_exception_handler(_request: Request, exc: AppException) -> JSONResponse:
    """Handle domain-specific AppException subclasses."""
    return JSONResponse(
        status_code=exc.status_code,
        content=_build_error_body(exc.message, exc.code, exc.status_code, exc.details),
    )


async def _http_exception_handler(_request: Request, exc: HTTPException) -> JSONResponse:
    """Handle FastAPI HTTPException with consistent error format."""
    return JSONResponse(
        status_code=exc.status_code,
        content=_build_error_body(
            message=str(exc.detail),
            code="HTTP_ERROR",
            status=exc.status_code,
        ),
    )


import logging

logger = logging.getLogger("awsap.exceptions")


async def _unhandled_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    """Catch-all handler for unhandled exceptions with safe operational logging."""
    logger.exception(
        "Unhandled server exception on %s %s: %s",
        request.method,
        request.url.path,
        type(exc).__name__,
    )
    return JSONResponse(
        status_code=500,
        content=_build_error_body(
            message="Internal server error",
            code="INTERNAL_ERROR",
            status=500,
        ),
    )


def register_exception_handlers(app: FastAPI) -> None:
    """Register all exception handlers on the FastAPI application instance."""
    app.add_exception_handler(AppException, _app_exception_handler)  # type: ignore[arg-type]
    app.add_exception_handler(HTTPException, _http_exception_handler)  # type: ignore[arg-type]
    app.add_exception_handler(Exception, _unhandled_exception_handler)
