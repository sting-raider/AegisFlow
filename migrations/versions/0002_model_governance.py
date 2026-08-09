"""Add immutable model candidate review and promotion state."""

from typing import cast

from alembic import op
from sqlalchemy import Table

from apps.api.database import ModelCandidateRow, ModelReviewRow

revision = "0002_model_governance"
down_revision = "0001_initial"
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    cast(Table, ModelCandidateRow.__table__).create(bind=bind, checkfirst=True)
    cast(Table, ModelReviewRow.__table__).create(bind=bind, checkfirst=True)


def downgrade() -> None:
    bind = op.get_bind()
    cast(Table, ModelReviewRow.__table__).drop(bind=bind, checkfirst=True)
    cast(Table, ModelCandidateRow.__table__).drop(bind=bind, checkfirst=True)
