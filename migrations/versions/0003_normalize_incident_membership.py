"""Normalize incident membership and add bounded grouping context."""

from __future__ import annotations

import json
from collections import defaultdict
from typing import Any

import sqlalchemy as sa
from alembic import op

revision = "0003_incident_membership"
down_revision = "0002_model_governance"
branch_labels = None
depends_on = None


def _alert_ids(value: object) -> list[str]:
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except json.JSONDecodeError:
            return []
    if not isinstance(value, list):
        return []
    return [str(item) for item in value]


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    incident_columns = {item["name"] for item in inspector.get_columns("incidents")}
    if "grouping_context" not in incident_columns:
        op.add_column("incidents", sa.Column("grouping_context", sa.JSON(), nullable=True))
    if "incident_alerts" not in inspector.get_table_names():
        op.create_table(
            "incident_alerts",
            sa.Column(
                "alert_id",
                sa.String(length=36),
                sa.ForeignKey("alerts.id", ondelete="CASCADE"),
                primary_key=True,
            ),
            sa.Column(
                "incident_id",
                sa.String(length=36),
                sa.ForeignKey("incidents.id", ondelete="CASCADE"),
                nullable=False,
            ),
        )
    membership = sa.table(
        "incident_alerts",
        sa.column("alert_id", sa.String(length=36)),
        sa.column("incident_id", sa.String(length=36)),
    )
    indexes = {item["name"] for item in sa.inspect(bind).get_indexes("incident_alerts")}
    if "ix_incident_alerts_incident_id" not in indexes:
        op.create_index(
            "ix_incident_alerts_incident_id",
            "incident_alerts",
            ["incident_id"],
            unique=False,
        )

    seen = {
        str(value)
        for value in bind.execute(sa.select(membership.c.alert_id)).scalars()
    }
    pending: list[dict[str, Any]] = []
    for row in bind.execute(sa.text("SELECT id, alert_ids FROM incidents")).mappings():
        for alert_id in _alert_ids(row["alert_ids"]):
            if alert_id in seen:
                continue
            seen.add(alert_id)
            pending.append({"alert_id": alert_id, "incident_id": str(row["id"])})
            if len(pending) == 1_000:
                bind.execute(membership.insert(), pending)
                pending.clear()
    if pending:
        bind.execute(membership.insert(), pending)


def downgrade() -> None:
    bind = op.get_bind()
    incident_table = sa.table(
        "incidents",
        sa.column("id", sa.String(length=36)),
        sa.column("alert_ids", sa.JSON()),
    )
    grouped: defaultdict[str, list[str]] = defaultdict(list)
    rows = bind.execute(
        sa.text(
            "SELECT incident_id, alert_id FROM incident_alerts "
            "ORDER BY incident_id, alert_id"
        )
    ).mappings()
    for row in rows:
        grouped[str(row["incident_id"])].append(str(row["alert_id"]))
    for incident_id, alert_ids in grouped.items():
        bind.execute(
            sa.update(incident_table)
            .where(incident_table.c.id == incident_id)
            .values(alert_ids=alert_ids)
        )
    op.drop_index("ix_incident_alerts_incident_id", table_name="incident_alerts")
    op.drop_table("incident_alerts")
    op.drop_column("incidents", "grouping_context")
