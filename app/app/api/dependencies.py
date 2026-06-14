from app.services.scans import ScanService


async def get_scan_service() -> ScanService:
    """Provide the scan service for request handlers."""
    return ScanService()
