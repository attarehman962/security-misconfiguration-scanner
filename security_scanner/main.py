from fastapi import FastAPI

from security_scanner.api.v1.routes import (
    auth_router,
    health_router,
    reports_router,
    scans_router,
    scrapes_router,
)
from security_scanner.core import get_settings, register_exception_handlers


def create_app() -> FastAPI:
    """Create and configure the FastAPI application."""
    settings = get_settings()
    app = FastAPI(
        title=settings.app_name,
        version=settings.api_version,
        debug=settings.debug,
    )

    register_exception_handlers(app)
    app.include_router(health_router, prefix="/api/v1")
    app.include_router(scans_router, prefix="/api/v1")
    app.include_router(scrapes_router, prefix="/api/v1")
    app.include_router(reports_router, prefix="/api/v1")
    app.include_router(auth_router, prefix="/api/v1")

    return app


app = create_app()
