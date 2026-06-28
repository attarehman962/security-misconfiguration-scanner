from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import Response
from sqlalchemy.orm import Session

from security_scanner.api.v1.dependencies import get_current_user, get_db
from security_scanner.crud.scan import get_scan_for_user
from security_scanner.models import User
from security_scanner.models.scan_record import ScanRecordStatus
from security_scanner.reporting.pdf_generator import generate_pdf_report
from security_scanner.schemas.reports import build_report_data

router = APIRouter(tags=["reports"])

DBDependency = Annotated[Session, Depends(get_db)]
CurrentUserDependency = Annotated[User, Depends(get_current_user)]


@router.get("/scans/{scan_id}/report")
def get_scan_report_pdf(
    scan_id: int,
    db: DBDependency,
    current_user: CurrentUserDependency,
) -> Response:
    """Generate and return a PDF report for a completed scan."""
    scan = get_scan_for_user(db, scan_id=scan_id, user_id=current_user.id)
    if scan is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scan not found.",
        )

    if scan.status is not ScanRecordStatus.COMPLETED:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Scan is not complete (current status: {scan.status}).",
        )

    report_data = build_report_data(scan)
    pdf_bytes = generate_pdf_report(report_data)

    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={
            "Content-Disposition": (
                f'attachment; filename="scan_report_{scan_id}.pdf"'
            )
        },
    )
