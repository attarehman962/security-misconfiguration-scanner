class ScanServiceError(Exception):
    """Base exception for scan service failures."""


class InvalidScanTargetError(ScanServiceError):
    """Raised when a scan target violates scanner business rules."""


class ScanNotFoundError(ScanServiceError):
    """Raised when a requested scan cannot be found."""
