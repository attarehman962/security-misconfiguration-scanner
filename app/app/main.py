from fastapi import FastAPI

from app.api.routes import scans_router
from app.core.config import get_settings
from app.core.exceptions import register_exception_handlers


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

    return app


app = create_app()
