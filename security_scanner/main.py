from fastapi import FastAPI

from security_scanner.api.v1.routes import (
    auth,
    health,
    reports,
    scans,
    scrapes,
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
    app.include_router(health.router, prefix="/api/v1")
    app.include_router(scans.router, prefix="/api/v1")
    app.include_router(scrapes.router, prefix="/api/v1")
    app.include_router(reports.router, prefix="/api/v1")
    app.include_router(auth.router, prefix="/api/v1")

    return app


app = create_app()
