"""API v1 route exports."""

from security_scanner.api.v1.routes.auth import router as auth_router
from security_scanner.api.v1.routes.health import router as health_router
from security_scanner.api.v1.routes.reports import router as reports_router
from security_scanner.api.v1.routes.scans import router as scans_router
from security_scanner.api.v1.routes.scrapes import router as scrapes_router

__all__ = [
    "auth_router",
    "health_router",
    "reports_router",
    "scans_router",
    "scrapes_router",
]
