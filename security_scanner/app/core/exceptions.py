import logging
from typing import cast

from fastapi import FastAPI, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.types import ExceptionHandler

from security_scanner.app.schemas.errors import ErrorResponse, FieldValidationError
from security_scanner.app.services.exceptions import (
    InvalidScanTargetError,
    ScanNotFoundError,
)

logger = logging.getLogger(__name__)


def _field_name(location: tuple[object, ...]) -> str:
    """Convert a FastAPI validation location into a client-facing field name."""
    location_parts = [str(part) for part in location]
    if location_parts and location_parts[0] in {"body", "query", "path"}:
        location_parts = location_parts[1:]
    return ".".join(location_parts) or "request"


async def validation_exception_handler(
    request: Request,
    exc: RequestValidationError,
) -> JSONResponse:
    """Return a consistent response for request validation errors."""
    detail = [
        FieldValidationError(
            field=_field_name(tuple(error["loc"])),
            message=str(error["msg"]),
            type=str(error["type"]),
        ).model_dump()
        for error in exc.errors()
    ]

    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
        content=ErrorResponse(error="validation_error", detail=detail).model_dump(),
    )


async def scan_not_found_exception_handler(
    request: Request,
    exc: ScanNotFoundError,
) -> JSONResponse:
    """Return a consistent response for missing scan resources."""
    return JSONResponse(
        status_code=status.HTTP_404_NOT_FOUND,
        content=ErrorResponse(error="not_found", detail=str(exc)).model_dump(),
    )


async def invalid_scan_target_exception_handler(
    request: Request,
    exc: InvalidScanTargetError,
) -> JSONResponse:
    """Return a consistent response for business-rule scan rejections."""
    return JSONResponse(
        status_code=status.HTTP_400_BAD_REQUEST,
        content=ErrorResponse(error="bad_request", detail=str(exc)).model_dump(),
    )


async def unhandled_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    """Return a sanitized response for unexpected server errors."""
    logger.exception(
        "Unhandled exception while processing %s %s",
        request.method,
        request.url.path,
    )
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content=ErrorResponse(
            error="internal_server_error",
            detail="An unexpected server error occurred.",
        ).model_dump(),
    )


def register_exception_handlers(app: FastAPI) -> None:
    """Register application-wide exception handlers."""
    app.add_exception_handler(
        RequestValidationError,
        cast(ExceptionHandler, validation_exception_handler),
    )
    app.add_exception_handler(
        ScanNotFoundError,
        cast(ExceptionHandler, scan_not_found_exception_handler),
    )
    app.add_exception_handler(
        InvalidScanTargetError,
        cast(ExceptionHandler, invalid_scan_target_exception_handler),
    )
    app.add_exception_handler(
        Exception,
        cast(ExceptionHandler, unhandled_exception_handler),
    )
