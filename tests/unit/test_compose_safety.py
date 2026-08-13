from __future__ import annotations

from pathlib import Path

import yaml


def test_local_redis_uses_aof_without_redundant_automatic_rdb_snapshots() -> None:
    compose = yaml.safe_load(Path("compose.yml").read_text(encoding="utf-8"))
    command = compose["services"]["redis"]["command"]

    assert command[command.index("--appendonly") + 1] == "yes"
    assert command[command.index("--save") + 1] == ""
    assert command[command.index("--maxmemory-policy") + 1] == "allkeys-lru"


def test_base_compose_waits_for_api_readiness_before_dashboard() -> None:
    compose = yaml.safe_load(Path("compose.yml").read_text(encoding="utf-8"))
    api = compose["services"]["api"]
    dashboard = compose["services"]["dashboard"]

    assert "/health/ready" in " ".join(api["healthcheck"]["test"])
    assert dashboard["depends_on"]["api"]["condition"] == "service_healthy"
