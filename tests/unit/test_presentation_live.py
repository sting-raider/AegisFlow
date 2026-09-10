from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from scripts import presentation_live


def test_live_launcher_starts_only_core_services_then_host_sensor(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[list[str], Path, dict[str, str]]] = []

    def capture(
        command: list[str], *, root: Path, environment: dict[str, str]
    ) -> None:
        calls.append((command, root, environment.copy()))
        if command[0] != "docker":
            raise KeyboardInterrupt

    monkeypatch.setattr(presentation_live, "_run", capture)

    assert presentation_live.main(["--interface", "Wi-Fi"]) == 0
    preflight, start, sensor, stop = calls
    assert preflight[0][-3:] == ["down", "--remove-orphans", "--volumes"]
    assert start[0][:4] == ["docker", "compose", "--project-name", "aegisflow-live"]
    assert start[0][-5:] == list(presentation_live.CORE_SERVICES)
    assert "sensor" not in start[0][-5:]
    assert sensor[0][-6:] == [
        "-m",
        "services.sensor.main",
        "--mode",
        "live",
        "--interface",
        "Wi-Fi",
    ]
    assert sensor[2]["AEGISFLOW_REDIS_URL"] == "redis://127.0.0.1:6379/0"
    assert sensor[2]["AEGISFLOW_SAFE_SIMULATION_ENABLED"] == "1"
    assert sensor[2]["INTERFACE"] == "Wi-Fi"
    assert stop[0][-3:] == ["down", "--remove-orphans", "--volumes"]


def test_live_launcher_stop_does_not_start_sensor(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[list[str]] = []
    environments: list[dict[str, str]] = []

    def capture(
        command: list[str], *, environment: dict[str, str], **_kwargs: Any
    ) -> None:
        calls.append(command)
        environments.append(environment)

    monkeypatch.setattr(presentation_live, "_run", capture)

    assert presentation_live.main(["--stop"]) == 0
    assert len(calls) == 1
    assert calls[0][-3:] == ["down", "--remove-orphans", "--volumes"]
    assert environments[0]["INTERFACE"] == "stop-only-placeholder"
