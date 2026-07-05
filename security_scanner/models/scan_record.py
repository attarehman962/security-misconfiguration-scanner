from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import TYPE_CHECKING

from sqlalchemy import DateTime, Enum, Float, ForeignKey, String, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from security_scanner.db import Base

if TYPE_CHECKING:
    from security_scanner.models.finding import FindingRecord


class ScanRecordStatus(StrEnum):
    """Lifecycle states of a scan job."""

    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


class ScanRecord(Base):
    """Persists one security scan and its lifecycle metadata."""

    __tablename__ = "scans"

    # ── Primary key ───────────────────────────────────────────────────────────
    id: Mapped[int] = mapped_column(primary_key=True, index=True)

    # ── Ownership ─────────────────────────────────────────────────────────────
    user_id: Mapped[int] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    # ── Scan target ───────────────────────────────────────────────────────────
    url: Mapped[str] = mapped_column(String(2048), nullable=False)

    # ── Lifecycle status ──────────────────────────────────────────────────────
    status: Mapped[ScanRecordStatus] = mapped_column(
        Enum(
            ScanRecordStatus,
            name="scanrecordstatus",
            native_enum=True,
            values_callable=lambda enum_cls: [e.value for e in enum_cls],
        ),
        nullable=False,
        default=ScanRecordStatus.PENDING,
    )

    # ── Timestamps ────────────────────────────────────────────────────────────
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )

    completed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    # ── Risk assessment ───────────────────────────────────────────────────────
    risk_score: Mapped[float | None] = mapped_column(
        Float,
        nullable=True,
        default=None,
        comment="Computed risk score after scan completes (0.0 - 100.0)",
    )

    risk_level: Mapped[str | None] = mapped_column(
        String(50),
        nullable=True,
        default=None,
        comment="Human-readable risk level: none, low, medium, high, critical",
    )

    error_message: Mapped[str | None] = mapped_column(
        String(2048),
        nullable=True,
        default=None,
        comment="Failure reason when a scan job does not complete.",
    )

    # ── Relationships ─────────────────────────────────────────────────────────
    findings: Mapped[list[FindingRecord]] = relationship(
        "FindingRecord",
        back_populates="scan",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )
