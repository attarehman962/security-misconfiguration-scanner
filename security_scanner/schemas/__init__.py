"""Pydantic request and response schemas."""

from security_scanner.schemas.auth import Token, UserCreate, UserLogin, UserPublic
from security_scanner.schemas.errors import ErrorResponse, FieldValidationError
from security_scanner.schemas.scans import (
    FindingResponse,
    HealthResponse,
    ScanAcceptedResponse,
    ScanCreateRequest,
    ScanResponse,
    ScanResultResponse,
    ScanStartRequest,
    ScanStatusResponse,
    scan_result_to_response,
)
from security_scanner.schemas.scrape import (
    ScrapedItemResponse,
    ScrapeRequest,
    ScrapeResponse,
    StructuredScrapeRequest,
    scrape_result_to_response,
)

__all__ = [
    "ErrorResponse",
    "FieldValidationError",
    "FindingResponse",
    "HealthResponse",
    "ScanAcceptedResponse",
    "ScanCreateRequest",
    "ScanResponse",
    "ScanResultResponse",
    "ScanStartRequest",
    "ScanStatusResponse",
    "ScrapedItemResponse",
    "ScrapeRequest",
    "ScrapeResponse",
    "StructuredScrapeRequest",
    "Token",
    "UserCreate",
    "UserLogin",
    "UserPublic",
    "scan_result_to_response",
    "scrape_result_to_response",
]
