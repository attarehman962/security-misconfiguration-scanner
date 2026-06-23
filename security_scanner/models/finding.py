"""Finding model — a single security check result within a scan."""

from typing import TYPE_CHECKING

from sqlalchemy import String, Text, ForeignKey, Enum as SqlEnum
from sqlalchemy.orm import Mapped, mapped_column, relationship

from security_scanner.db import Base
from security_scanner.models import Severity, Status

if TYPE_CHECKING:
    from security_scanner.models.scan_record import ScanRecord

class Finding(Base):
    """Represents the result of one security check during a scan."""

    __tablename__ = "findings"

    id: Mapped[int] = mapped_column(primary_key=True)
    scan_id: Mapped[int] = mapped_column(
        ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True
    )
    check_name: Mapped[str] = mapped_column(String(255), nullable=False)
    status: Mapped[Status] = mapped_column(SqlEnum(Status), nullable=False)
    severity: Mapped[Severity] = mapped_column(SqlEnum(Severity), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    remediation: Mapped[str] = mapped_column(Text, nullable=False)

    scan: Mapped["ScanRecord"] = relationship("ScanRecord", back_populates="findings")
