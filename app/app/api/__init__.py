"""API layer for route modules and FastAPI dependencies."""

from app.api.dependencies import get_scan_service

__all__ = ["get_scan_service"]
