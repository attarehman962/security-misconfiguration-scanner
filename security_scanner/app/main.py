from fastapi import FastAPI

from security_scanner.app.api.routes import (
    auth_router,
    scan_router,
    scans_router,
    scrape_router,
)
from security_scanner.app.core.config import get_settings
from security_scanner.app.core.exceptions import register_exception_handlers


def create_app() -> FastAPI:
    """Create and configure the FastAPI application."""
    settings = get_settings()
    app = FastAPI(
        title=settings.app_name,
        version=settings.api_version,
        debug=settings.debug,
    )

    register_exception_handlers(app)
    app.include_router(scans_router, prefix="/api/v1")
    app.include_router(scan_router, prefix="/api/v1")
    app.include_router(scrape_router, prefix="/api/v1")
    app.include_router(auth_router, prefix="/api/v1")

    return app


app = create_app()
