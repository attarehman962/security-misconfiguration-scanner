"""create users scans findings scraped_jobs tables

Revision ID: d951df286938
Revises: 
Create Date: 2026-06-23 12:39:46.108062

"""
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "d951df286938"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "users",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("email", sa.String(length=255), nullable=False),
        sa.Column("hashed_password", sa.String(length=255), nullable=False),
        sa.Column("is_active", sa.Boolean(), server_default="true", nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_users_email"), "users", ["email"], unique=True)
    op.create_index(op.f("ix_users_id"), "users", ["id"], unique=False)
    op.create_table(
        "scans",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("user_id", sa.Integer(), nullable=False),
        sa.Column("url", sa.String(length=2048), nullable=False),
        sa.Column(
            "status",
            sa.Enum(
                "pending",
                "running",
                "completed",
                "failed",
                name="scanrecordstatus",
            ),
            nullable=False,
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "risk_score",
            sa.Float(),
            nullable=True,
            comment="Computed risk score after scan completes (0.0 - 100.0)",
        ),
        sa.Column(
            "risk_level",
            sa.String(length=50),
            nullable=True,
            comment="Human-readable risk level: none, low, medium, high, critical",
        ),
        sa.Column(
            "error_message",
            sa.String(length=2048),
            nullable=True,
            comment="Failure reason when a scan job does not complete.",
        ),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_scans_id"), "scans", ["id"], unique=False)
    op.create_index(op.f("ix_scans_user_id"), "scans", ["user_id"], unique=False)
    op.create_table(
        "scraped_jobs",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("user_id", sa.Integer(), nullable=False),
        sa.Column("source_url", sa.String(length=2048), nullable=False),
        sa.Column("title", sa.String(length=500), nullable=False),
        sa.Column("company", sa.String(length=255), nullable=True),
        sa.Column("location", sa.String(length=255), nullable=True),
        sa.Column("date_posted", sa.DateTime(timezone=True), nullable=True),
        sa.Column("scraped_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        op.f("ix_scraped_jobs_user_id"),
        "scraped_jobs",
        ["user_id"],
        unique=False,
    )
    op.create_table(
        "findings",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("scan_id", sa.Integer(), nullable=False),
        sa.Column("check_name", sa.String(length=255), nullable=False),
        sa.Column("status", sa.Enum("PASS", "FAIL", name="status"), nullable=False),
        sa.Column(
            "severity",
            sa.Enum("CRITICAL", "INFO", "LOW", "MEDIUM", "HIGH", name="severity"),
            nullable=False,
        ),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("remediation", sa.Text(), nullable=False),
        sa.ForeignKeyConstraint(["scan_id"], ["scans.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        op.f("ix_findings_scan_id"),
        "findings",
        ["scan_id"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index(op.f("ix_findings_scan_id"), table_name="findings")
    op.drop_table("findings")
    op.drop_index(op.f("ix_scraped_jobs_user_id"), table_name="scraped_jobs")
    op.drop_table("scraped_jobs")
    op.drop_index(op.f("ix_scans_user_id"), table_name="scans")
    op.drop_index(op.f("ix_scans_id"), table_name="scans")
    op.drop_table("scans")
    op.drop_index(op.f("ix_users_id"), table_name="users")
    op.drop_index(op.f("ix_users_email"), table_name="users")
    op.drop_table("users")
