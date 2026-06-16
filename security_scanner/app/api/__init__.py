"""API layer for route modules and FastAPI dependencies."""

from security_scanner.app.api.dependencies import get_scan_service

__all__ = ["get_scan_service"]
