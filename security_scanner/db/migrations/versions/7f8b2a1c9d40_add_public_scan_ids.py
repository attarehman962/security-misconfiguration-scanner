"""add public scan ids

Revision ID: 7f8b2a1c9d40
Revises: d951df286938
Create Date: 2026-07-10 00:00:00.000000

"""
from collections.abc import Sequence
from uuid import uuid4

import sqlalchemy as sa
from alembic import op

revision: str = "7f8b2a1c9d40"
down_revision: str | None = "d951df286938"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("scans", sa.Column("public_id", sa.String(length=32), nullable=True))

    scans_table = sa.table(
        "scans",
        sa.column("id", sa.Integer()),
        sa.column("public_id", sa.String(length=32)),
    )
    bind = op.get_bind()
    scan_ids = bind.execute(sa.select(scans_table.c.id)).scalars().all()
    for scan_id in scan_ids:
        bind.execute(
            scans_table.update()
            .where(scans_table.c.id == scan_id)
            .values(public_id=uuid4().hex)
        )

    with op.batch_alter_table("scans") as batch_op:
        batch_op.alter_column(
            "public_id",
            existing_type=sa.String(length=32),
            nullable=False,
        )
        batch_op.create_index(
            batch_op.f("ix_scans_public_id"),
            ["public_id"],
            unique=True,
        )


def downgrade() -> None:
    with op.batch_alter_table("scans") as batch_op:
        batch_op.drop_index(batch_op.f("ix_scans_public_id"))
        batch_op.drop_column("public_id")
