"""Versioned API route modules."""

from app.api.routes.auth import router as auth_router
from app.api.routes.scan import router as scan_router
from app.api.routes.scans import router as scans_router
from app.api.routes.scrape import router as scrape_router

__all__ = ["auth_router", "scan_router", "scans_router", "scrape_router"]
