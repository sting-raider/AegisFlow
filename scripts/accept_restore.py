from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import tempfile
import time
from collections.abc import Mapping
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast

from scripts.restore_fixture import SMOKE_PREFIX, SNAPSHOT_PREFIX

PROJECT = "aegisflow-restore-acceptance"
API_CONTAINER = "aegisflow-restore-api-acceptance"
COMPOSE = [
    "docker",
    "compose",
    "--project-name",
    PROJECT,
    "-f",
    "compose.yml",
    "-f",
    "compose.demo.yml",
]
DATABASE_URL = "postgresql+psycopg://aegisflow:aegisflow-restore-only@postgres:5432/aegisflow"


class RestoreAcceptanceError(RuntimeError):
    pass


def compare_snapshots(before: Mapping[str, Any], after: Mapping[str, Any]) -> list[str]:
    failures: list[str] = []
    before_tables = before.get("tables")
    after_tables = after.get("tables")
    if not isinstance(before_tables, dict) or not isinstance(after_tables, dict):
        return ["snapshot tables are missing"]
    if set(before_tables) != set(after_tables):
        failures.append("restored table set differs from backup source")
    for name in sorted(set(before_tables) | set(after_tables)):
        expected = before_tables.get(name)
        actual = after_tables.get(name)
        if not isinstance(expected, dict) or not isinstance(actual, dict):
            failures.append(f"table {name} snapshot is missing")
            continue
        if expected.get("count") != actual.get("count"):
            failures.append(f"table {name} row count differs after restore")
        if expected.get("identity_sha256") != actual.get("identity_sha256"):
            failures.append(f"table {name} primary identities differ after restore")
    return failures


def _run_text(
    arguments: list[str],
    *,
    env: Mapping[str, str],
    timeout: float = 180,
    check: bool = True,
) -> subprocess.CompletedProcess[str]:
    try:
        result = subprocess.run(
            arguments,
            text=True,
            capture_output=True,
            check=False,
            env=dict(env),
            timeout=timeout,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise RestoreAcceptanceError("bounded local container command could not complete") from exc
    if check and result.returncode != 0:
        raise RestoreAcceptanceError("local restore command returned a nonzero status")
    return result


def _compose(
    *arguments: str,
    env: Mapping[str, str],
    timeout: float = 180,
    check: bool = True,
) -> subprocess.CompletedProcess[str]:
    return _run_text(
        [*COMPOSE, *arguments],
        env=env,
        timeout=timeout,
        check=check,
    )


def _parse_prefixed(output: str, prefix: str) -> dict[str, Any]:
    for line in reversed(output.splitlines()):
        if line.startswith(prefix):
            try:
                payload = json.loads(line.removeprefix(prefix))
            except json.JSONDecodeError as exc:
                raise RestoreAcceptanceError("acceptance helper returned invalid JSON") from exc
            if isinstance(payload, dict):
                return cast(dict[str, Any], payload)
    raise RestoreAcceptanceError("acceptance helper did not return its result marker")


def _assert_project_absent(env: Mapping[str, str]) -> None:
    containers = _run_text(
        [
            "docker",
            "ps",
            "-a",
            "--filter",
            f"label=com.docker.compose.project={PROJECT}",
            "--format",
            "{{.ID}}",
        ],
        env=env,
        timeout=30,
    ).stdout.strip()
    volumes = _run_text(
        [
            "docker",
            "volume",
            "ls",
            "--filter",
            f"label=com.docker.compose.project={PROJECT}",
            "--format",
            "{{.Name}}",
        ],
        env=env,
        timeout=30,
    ).stdout.strip()
    named_api = _run_text(
        ["docker", "container", "inspect", API_CONTAINER],
        env=env,
        timeout=30,
        check=False,
    )
    if containers or volumes or named_api.returncode == 0:
        raise RestoreAcceptanceError(
            "refusing to replace a pre-existing restore-acceptance container or volume"
        )


def _wait_postgres(env: Mapping[str, str]) -> None:
    deadline = time.monotonic() + 90
    while time.monotonic() < deadline:
        result = _compose(
            "exec",
            "-T",
            "postgres",
            "pg_isready",
            "-U",
            "aegisflow",
            "-d",
            "aegisflow",
            env=env,
            timeout=10,
            check=False,
        )
        if result.returncode == 0:
            return
        time.sleep(0.5)
    raise RestoreAcceptanceError("disposable PostgreSQL did not become ready")


def _helper(command: str, env: Mapping[str, str]) -> dict[str, Any]:
    result = _compose(
        "run",
        "--rm",
        "--no-deps",
        "--env",
        f"AEGISFLOW_DATABASE_URL={DATABASE_URL}",
        "api",
        "python",
        "-m",
        "scripts.restore_fixture",
        command,
        env=env,
        timeout=240,
    )
    return _parse_prefixed(result.stdout, SNAPSHOT_PREFIX)


def _dump_database(env: Mapping[str, str], destination: Path) -> tuple[int, str]:
    try:
        result = subprocess.run(
            [
                *COMPOSE,
                "exec",
                "-T",
                "postgres",
                "pg_dump",
                "-U",
                "aegisflow",
                "-d",
                "aegisflow",
                "-Fc",
                "--no-owner",
                "--no-acl",
            ],
            capture_output=True,
            check=False,
            env=dict(env),
            timeout=180,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise RestoreAcceptanceError("bounded pg_dump did not complete") from exc
    if result.returncode != 0 or not result.stdout:
        raise RestoreAcceptanceError("pg_dump did not produce a nonempty custom-format backup")
    destination.write_bytes(result.stdout)
    return len(result.stdout), hashlib.sha256(result.stdout).hexdigest()


def _restore_database(env: Mapping[str, str], source: Path) -> None:
    _compose(
        "exec",
        "-T",
        "postgres",
        "psql",
        "-U",
        "aegisflow",
        "-d",
        "postgres",
        "-v",
        "ON_ERROR_STOP=1",
        "-c",
        "DROP DATABASE aegisflow WITH (FORCE);",
        env=env,
    )
    _compose(
        "exec",
        "-T",
        "postgres",
        "createdb",
        "-U",
        "aegisflow",
        "aegisflow",
        env=env,
    )
    try:
        result = subprocess.run(
            [
                *COMPOSE,
                "exec",
                "-T",
                "postgres",
                "pg_restore",
                "-U",
                "aegisflow",
                "-d",
                "aegisflow",
                "--exit-on-error",
                "--no-owner",
                "--no-acl",
            ],
            input=source.read_bytes(),
            capture_output=True,
            check=False,
            env=dict(env),
            timeout=180,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise RestoreAcceptanceError("bounded pg_restore did not complete") from exc
    if result.returncode != 0:
        raise RestoreAcceptanceError("pg_restore returned a nonzero status")


def _migration(env: Mapping[str, str]) -> None:
    _compose(
        "run",
        "--rm",
        "--no-deps",
        "--env",
        f"AEGISFLOW_DATABASE_URL={DATABASE_URL}",
        "api",
        "python",
        "-m",
        "scripts.migrate",
        env=env,
        timeout=180,
    )


def _api_smoke(env: Mapping[str, str]) -> dict[str, Any]:
    _compose(
        "run",
        "-d",
        "--rm",
        "--no-deps",
        "--name",
        API_CONTAINER,
        "--env",
        f"AEGISFLOW_DATABASE_URL={DATABASE_URL}",
        "--env",
        "AEGISFLOW_DEMO=1",
        "--env",
        "AEGISFLOW_DEMO_SEED=0",
        "--env",
        "AEGISFLOW_CONSUME_REDIS=0",
        "--env",
        "AEGISFLOW_RETENTION_ENABLED=0",
        "api",
        env=env,
        timeout=60,
    )
    deadline = time.monotonic() + 120
    while time.monotonic() < deadline:
        result = _run_text(
            [
                "docker",
                "exec",
                API_CONTAINER,
                "python",
                "-m",
                "scripts.restore_fixture",
                "api-smoke",
            ],
            env=env,
            timeout=15,
            check=False,
        )
        if result.returncode == 0:
            return _parse_prefixed(result.stdout, SMOKE_PREFIX)
        time.sleep(0.5)
    raise RestoreAcceptanceError("restored API did not pass its bounded smoke check")


def run_acceptance(output: Path) -> dict[str, object]:
    started_at = datetime.now(UTC)
    started = time.perf_counter()
    env = dict(os.environ)
    env["AEGISFLOW_DB_PASSWORD"] = "aegisflow-restore-only"
    _assert_project_absent(env)
    claimed = True
    timings: dict[str, float] = {}
    before: dict[str, Any] = {}
    after: dict[str, Any] = {}
    api_result: dict[str, Any] = {}
    backup_size = 0
    backup_sha256 = ""
    cleanup_passed = False
    try:
        stage = time.perf_counter()
        _compose("build", "api", env=env, timeout=600)
        _compose("up", "-d", "postgres", "redis", env=env, timeout=180)
        _wait_postgres(env)
        timings["startup_seconds"] = time.perf_counter() - stage

        stage = time.perf_counter()
        _migration(env)
        _helper("seed", env)
        before = _helper("snapshot", env)
        timings["migration_and_seed_seconds"] = time.perf_counter() - stage

        with tempfile.TemporaryDirectory(prefix="aegisflow-restore-") as temporary:
            dump_path = Path(temporary) / "aegisflow.dump"
            stage = time.perf_counter()
            backup_size, backup_sha256 = _dump_database(env, dump_path)
            timings["backup_seconds"] = time.perf_counter() - stage
            stage = time.perf_counter()
            _restore_database(env, dump_path)
            timings["destroy_and_restore_seconds"] = time.perf_counter() - stage

        stage = time.perf_counter()
        _migration(env)
        after = _helper("snapshot", env)
        failures = compare_snapshots(before, after)
        timings["validation_seconds"] = time.perf_counter() - stage
        if failures:
            raise RestoreAcceptanceError("; ".join(failures))

        stage = time.perf_counter()
        api_result = _api_smoke(env)
        timings["api_smoke_seconds"] = time.perf_counter() - stage
    finally:
        if claimed:
            inspected = _run_text(
                [
                    "docker",
                    "container",
                    "inspect",
                    "--format",
                    "{{index .Config.Labels \"com.docker.compose.project\"}}",
                    API_CONTAINER,
                ],
                env=env,
                timeout=30,
                check=False,
            )
            if inspected.returncode == 0 and inspected.stdout.strip() == PROJECT:
                _run_text(
                    ["docker", "stop", "--timeout", "10", API_CONTAINER],
                    env=env,
                    timeout=30,
                    check=False,
                )
            cleanup = _compose(
                "down",
                "-v",
                "--remove-orphans",
                env=env,
                timeout=120,
                check=False,
            )
            cleanup_passed = cleanup.returncode == 0

    report: dict[str, object] = {
        "schema_version": "1.0.0",
        "generated_at": started_at.isoformat(),
        "completed_at": datetime.now(UTC).isoformat(),
        "scope": "disposable local PostgreSQL backup, destruction, restore, and API smoke",
        "safety": {
            "isolated_compose_project": PROJECT,
            "preexisting_project_replaced": False,
            "developer_volumes_touched": False,
            "backup_retained": False,
            "packet_payloads_stored": False,
            "external_targets": False,
        },
        "backup": {
            "format": "PostgreSQL custom",
            "bytes": backup_size,
            "sha256": backup_sha256,
        },
        "timing_seconds": {**timings, "total": time.perf_counter() - started},
        "validation": {
            "table_count": len(cast(dict[str, Any], before["tables"])),
            "counts_and_primary_identities_match": True,
            "required_entities": before["required_entity_tables"],
            "before": before["tables"],
            "after": after["tables"],
            "migration_version_before": before.get("migration_version"),
            "migration_version_after": after.get("migration_version"),
            "api_smoke": api_result,
            "cleanup_passed": cleanup_passed,
        },
        "verdict": {
            "passed": cleanup_passed and bool(api_result.get("passed")),
            "failures": [] if cleanup_passed else ["disposable project cleanup failed"],
        },
        "limitations": [
            "This drill validates local PostgreSQL mechanics, not a managed backup service.",
            "The fixture contains synthetic metadata only and no packet payloads.",
            "Operators must separately validate encryption, retention, access control, "
            "and off-host storage.",
        ],
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    return report


def main() -> None:
    parser = argparse.ArgumentParser(description="Run disposable PostgreSQL restore acceptance")
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("docs/acceptance/restore-local.json"),
    )
    args = parser.parse_args()
    try:
        report = run_acceptance(args.output)
    except RestoreAcceptanceError as exc:
        report = {
            "schema_version": "1.0.0",
            "generated_at": datetime.now(UTC).isoformat(),
            "scope": "disposable local PostgreSQL backup, destruction, restore, and API smoke",
            "safety": {
                "isolated_compose_project": PROJECT,
                "preexisting_project_replaced": False,
                "developer_volumes_touched": False,
                "backup_retained": False,
                "external_targets": False,
            },
            "verdict": {"passed": False, "failures": [str(exc)]},
        }
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2))
    if not cast(dict[str, Any], report["verdict"])["passed"]:
        raise SystemExit(2)


if __name__ == "__main__":
    main()
