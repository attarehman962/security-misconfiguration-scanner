from datetime import datetime, timezone

from app.schemas.scan import FindingResponse, ScanResponse


def create_mock_scan_result(target_url: str) -> ScanResponse:
    """Create a mock scan result using the final API response shape.

    This function is temporary. Later it will call the real scanner modules
    built in earlier days.
    """
    mock_finding = FindingResponse(
        check_name="security_headers",
        status="fail",
        severity="medium",
        description="Missing Content-Security-Policy header.",
        remediation="Add a strict Content-Security-Policy header.",
    )
    second_mock_finding = FindingResponse(
        check_name="x_frame_options",
        status="fail",
        severity="low",
        description="Missing X-Frame-Options header.",
        remediation="Add a strict X-Frame-Options header.",
    )

    return ScanResponse(
        url=target_url,
        timestamp=datetime.now(timezone.utc),
        findings=[mock_finding, second_mock_finding],
        total_score=85,
    )