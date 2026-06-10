"""Custom exceptions for the security scanner."""


class ScannerError(Exception):
    """Base exception for all scanner-related errors."""


class InvalidURLError(ScannerError):
    """Raised when the provided URL is empty, malformed, or unsupported."""


class NetworkError(ScannerError):
    """Raised when the scanner cannot reach the target over the network."""


class SSLError(ScannerError):
    """Raised when an SSL/TLS-specific failure occurs."""


class ScanTimeoutError(NetworkError):
    """Raised when a scan operation exceeds the allowed time limit."""
