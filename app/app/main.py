from fastapi import FastAPI, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from app.core.config import get_settings
from app.routers import auth, scan, scrape
from app.schemas.error import ValidationErrorDetail, ValidationErrorResponse


def create_app() -> FastAPI:
    """Create and configure the FastAPI application."""
    settings = get_settings()

    application = FastAPI(
        title=settings.app_name,
        version=settings.api_version,
        debug=settings.debug,
    )

    application.include_router(scan.router)
    application.include_router(auth.router)
    application.include_router(scrape.router)

    @application.exception_handler(RequestValidationError)
    async def validation_exception_handler(
        request: Request,
        exc: RequestValidationError,
    ) -> JSONResponse:
        """Return a custom 422 response for request validation errors."""
        validation_errors = [
            ValidationErrorDetail(
                field=".".join(str(location_part) for location_part in error["loc"]),
                message=str(error["msg"]),
                error_type=str(error["type"]),
            )
            for error in exc.errors()
        ]

        error_response = ValidationErrorResponse(
            message="Request validation failed. Check the submitted fields.",
            errors=validation_errors,
        )

        return JSONResponse(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            content=error_response.model_dump(mode="json"),
        )

    return application


app = create_app()