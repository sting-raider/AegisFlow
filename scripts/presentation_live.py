from __future__ import annotations

import argparse
import os
import subprocess
import sys
from collections.abc import Sequence
from pathlib import Path

PROJECT_NAME = "aegisflow-live"
CORE_SERVICES = ("postgres", "redis", "api", "detector", "dashboard")


def _run(command: Sequence[str], *, root: Path, environment: dict[str, str]) -> None:
    subprocess.run(command, cwd=root, env=environment, check=True)


def _compose_command(root: Path, *arguments: str) -> list[str]:
    return [
        "docker",
        "compose",
        "--project-name",
        PROJECT_NAME,
        "--file",
        str(root / "compose.yml"),
        "--file",
        str(root / "compose.live.yml"),
        *arguments,
    ]


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run the AegisFlow dashboard with explicit host live capture"
    )
    operation = parser.add_mutually_exclusive_group(required=True)
    operation.add_argument(
        "--interface",
        help='explicitly authorized host interface, for example "Wi-Fi" or eth0',
    )
    operation.add_argument(
        "--stop",
        action="store_true",
        help="stop the isolated live presentation stack",
    )
    return parser


def main(arguments: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(arguments)
    root = Path(__file__).resolve().parents[1]
    environment = os.environ.copy()

    if args.stop:
        _run(
            _compose_command(root, "down", "--remove-orphans"),
            root=root,
            environment=environment,
        )
        return 0

    interface = str(args.interface).strip()
    if not interface:
        _parser().error("--interface cannot be blank")
    environment["INTERFACE"] = interface
    environment["AEGISFLOW_REDIS_URL"] = "redis://127.0.0.1:6379/0"

    print(
        "PRIVACY WARNING: capturing only the explicitly authorized local interface "
        f"{interface!r}; packet payloads are not retained."
    )
    try:
        _run(
            _compose_command(
                root,
                "up",
                "--build",
                "--detach",
                "--wait",
                "--wait-timeout",
                "180",
                *CORE_SERVICES,
            ),
            root=root,
            environment=environment,
        )
        print("AegisFlow dashboard: http://127.0.0.1:5173")
        print("Live capture is running. Press Ctrl+C to stop AegisFlow.")
        _run(
            [
                sys.executable,
                "-m",
                "services.sensor.main",
                "--mode",
                "live",
                "--interface",
                interface,
            ],
            root=root,
            environment=environment,
        )
    except KeyboardInterrupt:
        print("Stopping live capture and isolated services...")
    finally:
        _run(
            _compose_command(root, "down", "--remove-orphans"),
            root=root,
            environment=environment,
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
