from __future__ import annotations

import pytest

from scripts.benchmark_pipeline import _require_local_service_url


@pytest.mark.parametrize(
    "url",
    [
        "redis://localhost:6379/0",
        "redis://redis:6379/0",
        "postgresql+psycopg://user:password@postgres:5432/aegisflow",
    ],
)
def test_pipeline_benchmark_accepts_only_local_compose_targets(url: str) -> None:
    assert _require_local_service_url(url, "service") == url


def test_pipeline_benchmark_refuses_external_targets() -> None:
    with pytest.raises(ValueError, match="localhost or the AegisFlow Compose network"):
        _require_local_service_url("redis://example.com:6379/0", "Redis URL")
