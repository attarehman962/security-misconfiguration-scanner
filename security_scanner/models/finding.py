from __future__ import annotations

from typing import TYPE_CHECKING

from sqlalchemy import Enum as SqlEnum
from sqlalchemy import ForeignKey, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from security_scanner.db import Base
from security_scanner.models.scan import Severity, Status

if TYPE_CHECKING:
    from security_scanner.models.scan_record import ScanRecord


class FindingRecord(Base):
    """Persisted database row for one security check finding."""

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

    scan: Mapped[ScanRecord] = relationship("ScanRecord", back_populates="findings")
