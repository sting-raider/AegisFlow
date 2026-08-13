from __future__ import annotations

import argparse
import json
import subprocess
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, TypedDict, cast

COMPOSE = ["docker", "compose", "-f", "compose.yml", "-f", "compose.demo.yml"]
STREAM = "aegisflow:detections"
GROUP = "api-core"
WORKER_NAME = "aegisflow-api-worker-acceptance"


class AcceptanceFailure(RuntimeError):
    pass


class ConsumerState(TypedDict):
    name: str
    pending: int
    idle: int
    inactive: int


def parse_consumers(raw: str) -> list[ConsumerState]:
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise AcceptanceFailure("Redis consumer state was not valid JSON") from exc
    if not isinstance(payload, list):
        raise AcceptanceFailure("Redis consumer state was not a list")
    result: list[ConsumerState] = []
    for item in payload:
        if not isinstance(item, dict):
            raise AcceptanceFailure("Redis consumer entry was not an object")
        try:
            result.append(
                {
                    "name": str(item["name"]),
                    "pending": max(0, int(item["pending"])),
                    "idle": max(0, int(item.get("idle", 0))),
                    "inactive": max(0, int(item.get("inactive", 0))),
                }
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise AcceptanceFailure("Redis consumer entry had invalid fields") from exc
    return result


def persisted_count(raw_logs: str) -> int:
    total = 0
    for line in raw_logs.splitlines():
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(item, dict) or item.get("event_type") != "detection_batch_persisted":
            continue
        value = item.get("published_count")
        if isinstance(value, int) and value > 0:
            total += value
    return total


def assess_recovery(
    *,
    workload: dict[str, Any],
    initial_worker_persisted: int,
    restarted_worker_persisted: int,
    survivor_persisted: int,
    abandoned_pending: int,
    abandoned_pending_recovered: bool,
) -> dict[str, object]:
    counts = cast(dict[str, Any], workload.get("counts", {}))
    queues = cast(dict[str, Any], workload.get("queues", {}))
    planned = int(counts.get("planned", -1))
    published = int(counts.get("published", -1))
    flows = int(counts.get("persisted_flows", -1))
    detections = int(counts.get("persisted_detections", -1))
    failures: list[str] = []
    if min(initial_worker_persisted, restarted_worker_persisted, survivor_persisted) <= 0:
        failures.append("every worker phase must durably persist at least one detection")
    if abandoned_pending <= 0:
        failures.append("the stopped worker did not own pending work")
    if not abandoned_pending_recovered:
        failures.append("abandoned pending work was not reclaimed")
    if not (planned == published == flows == detections and planned > 0):
        failures.append(
            "exact conservation failed "
            f"(planned={planned}, published={published}, flows={flows}, detections={detections})"
        )
    if int(queues.get("final_flow_depth", -1)) != 0:
        failures.append("flow consumer group did not return to zero depth")
    if int(queues.get("final_detection_depth", -1)) != 0:
        failures.append("persistence consumer group did not return to zero depth")
    return {
        "passed": not failures,
        "criteria": {
            "all_worker_phases_persisted": min(
                initial_worker_persisted,
                restarted_worker_persisted,
                survivor_persisted,
            )
            > 0,
            "stopped_worker_owned_pending_work": abandoned_pending > 0,
            "abandoned_work_reclaimed": abandoned_pending_recovered,
            "exact_conservation": planned == published == flows == detections and planned > 0,
            "queues_drained": (
                int(queues.get("final_flow_depth", -1)) == 0
                and int(queues.get("final_detection_depth", -1)) == 0
            ),
        },
        "failures": failures,
    }


def _run(arguments: list[str], *, check: bool = True) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(arguments, text=True, capture_output=True, check=False)
    if check and result.returncode != 0:
        detail = (result.stderr or result.stdout).strip()
        raise AcceptanceFailure(f"command failed ({' '.join(arguments)}): {detail}")
    return result


def _compose(*arguments: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    return _run([*COMPOSE, *arguments], check=check)


def _consumers() -> list[ConsumerState]:
    result = _compose(
        "exec",
        "-T",
        "redis",
        "redis-cli",
        "--json",
        "XINFO",
        "CONSUMERS",
        STREAM,
        GROUP,
    )
    return parse_consumers(result.stdout)


def _consumers_if_ready() -> list[ConsumerState] | None:
    try:
        return _consumers()
    except AcceptanceFailure:
        return None


def _container_hostname(name: str) -> str:
    return _run(["docker", "inspect", "--format", "{{.Config.Hostname}}", name]).stdout.strip()


def _logs(name: str, since: str) -> str:
    result = _run(["docker", "logs", "--since", since, name], check=False)
    return f"{result.stdout}\n{result.stderr}"


def _wait_until(predicate: Any, description: str, timeout_seconds: float) -> Any:
    deadline = time.monotonic() + timeout_seconds
    last: Any = None
    while time.monotonic() < deadline:
        last = predicate()
        if last:
            return last
        time.sleep(0.25)
    raise AcceptanceFailure(f"timed out waiting for {description}; last observation={last!r}")


def _start_worker() -> str:
    existing = _run(
        ["docker", "container", "inspect", WORKER_NAME],
        check=False,
    )
    if existing.returncode == 0:
        raise AcceptanceFailure(
            f"refusing to replace existing container {WORKER_NAME}; remove it after inspection"
        )
    _compose(
        "run",
        "-d",
        "--rm",
        "--no-deps",
        "--name",
        WORKER_NAME,
        "--env",
        "AEGISFLOW_RETENTION_ENABLED=0",
        "api",
    )
    hostname = _container_hostname(WORKER_NAME)
    consumer_name = f"api-{hostname}-"
    _wait_until(
        lambda: next(
            (item for item in _consumers() if item["name"].startswith(consumer_name)),
            None,
        ),
        "the extra API consumer to join the group",
        60,
    )
    return consumer_name


def _main_api_container() -> str:
    containers = [item for item in _compose("ps", "-q", "api").stdout.splitlines() if item]
    if len(containers) != 1:
        raise AcceptanceFailure(
            f"expected exactly one Compose API service, found {len(containers)}"
        )
    return containers[0]


def run_acceptance(
    *,
    duration_seconds: float,
    target_rate: float,
    output: Path,
    workload_output: Path,
) -> dict[str, object]:
    if duration_seconds < 60:
        raise AcceptanceFailure("multi-worker recovery requires at least 60 seconds")
    if target_rate <= 0:
        raise AcceptanceFailure("target rate must be positive")
    initial_status = cast(
        list[ConsumerState],
        _wait_until(
            _consumers_if_ready,
            "the persistence consumer group to become ready",
            60,
        ),
    )
    if any(item["pending"] for item in initial_status):
        raise AcceptanceFailure("persistence group must start with zero pending work")
    main_container = _main_api_container()
    started_at = datetime.now(UTC)
    since = started_at.isoformat().replace("+00:00", "Z")
    first_prefix = _start_worker()
    benchmark_dir = workload_output.resolve().parent
    benchmark_dir.mkdir(parents=True, exist_ok=True)
    workload_name = workload_output.name
    runner = subprocess.Popen(
        [
            *COMPOSE,
            "run",
            "--rm",
            "--no-deps",
            "--volume",
            f"{benchmark_dir}:/app/docs/benchmarks",
            "api",
            "python",
            "-m",
            "scripts.benchmark_sustained",
            "--duration-seconds",
            str(duration_seconds),
            "--target-rate",
            str(target_rate),
            "--p95-latency-budget-ms",
            "60000",
            "--drain-timeout-seconds",
            "180",
            "--output",
            f"/app/docs/benchmarks/{workload_name}",
        ],
        text=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
    )
    first_logs = ""
    second_logs = ""
    abandoned_pending = 0
    recovered = False
    try:

        def worker_has_pending() -> ConsumerState | None:
            if persisted_count(_logs(WORKER_NAME, since)) <= 0:
                return None
            for item in _consumers():
                if item["name"].startswith(first_prefix) and item["pending"] > 0:
                    return item
            return None

        pending_state = cast(
            ConsumerState,
            _wait_until(worker_has_pending, "the extra worker to own pending work", 60),
        )
        abandoned_pending = pending_state["pending"]
        first_logs = _logs(WORKER_NAME, since)
        _run(["docker", "kill", WORKER_NAME])
        _wait_until(
            lambda: _run(["docker", "container", "inspect", WORKER_NAME], check=False).returncode
            != 0,
            "the killed worker container to be removed",
            30,
        )

        def abandoned_recovered() -> bool:
            matching = [item for item in _consumers() if item["name"].startswith(first_prefix)]
            return bool(matching) and all(item["pending"] == 0 for item in matching)

        recovered = bool(
            _wait_until(
                abandoned_recovered,
                "the surviving API worker to reclaim abandoned work",
                75,
            )
        )
        second_prefix = _start_worker()
        _wait_until(
            lambda: len(_consumers()) >= 2,
            "the restarted replica to rejoin the consumer group",
            60,
        )
        timeout = duration_seconds + 300
        try:
            _, stderr = runner.communicate(timeout=timeout)
        except subprocess.TimeoutExpired as exc:
            runner.kill()
            runner.communicate()
            raise AcceptanceFailure("recovery workload timed out") from exc
        if runner.returncode not in (0, 2):
            raise AcceptanceFailure(f"recovery workload failed: {(stderr or '').strip()}")
        second_logs = _logs(WORKER_NAME, since)
        if not any(item["name"].startswith(second_prefix) for item in _consumers()):
            raise AcceptanceFailure("restarted worker disappeared before evidence collection")
    finally:
        if runner.poll() is None:
            runner.kill()
            runner.communicate()
        if _run(["docker", "container", "inspect", WORKER_NAME], check=False).returncode == 0:
            _run(["docker", "stop", "--timeout", "10", WORKER_NAME], check=False)

    workload = json.loads(workload_output.read_text(encoding="utf-8"))
    if not isinstance(workload, dict):
        raise AcceptanceFailure("workload report was not an object")
    main_count = persisted_count(_logs(main_container, since))
    first_count = persisted_count(first_logs)
    second_count = persisted_count(second_logs)
    verdict = assess_recovery(
        workload=workload,
        initial_worker_persisted=first_count,
        restarted_worker_persisted=second_count,
        survivor_persisted=main_count,
        abandoned_pending=abandoned_pending,
        abandoned_pending_recovered=recovered,
    )
    report: dict[str, object] = {
        "schema_version": "1.0.0",
        "generated_at": started_at.isoformat(),
        "completed_at": datetime.now(UTC).isoformat(),
        "scope": "local Compose multi-worker persistence partitioning and recovery",
        "safety": {
            "metadata_only": True,
            "payloads_stored": False,
            "external_targets": False,
            "automatic_blocking": False,
        },
        "configuration": {
            "duration_seconds": duration_seconds,
            "target_flows_per_second": target_rate,
            "claim_idle_ms": 30000,
            "controlled_failure": "SIGKILL of one acceptance-only API replica",
        },
        "worker_evidence": {
            "surviving_primary_persisted": main_count,
            "initial_replica_persisted_before_kill": first_count,
            "restarted_replica_persisted": second_count,
            "abandoned_pending_at_kill": abandoned_pending,
            "abandoned_pending_recovered": recovered,
        },
        "workload_report": workload_output.as_posix(),
        "workload_summary": {
            "counts": workload.get("counts"),
            "latency_ms": workload.get("latency_ms"),
            "queues": workload.get("queues"),
            "verdict": workload.get("verdict"),
        },
        "verdict": verdict,
        "limitations": [
            "This is a synthetic metadata-only single-host recovery drill, not a capacity claim.",
            "Per-worker counts are derived from structured durable-batch logs and may overlap on "
            "idempotent retry; exact database conservation is the authoritative total.",
        ],
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    return report


def main() -> None:
    parser = argparse.ArgumentParser(description="Exercise local multi-worker persistence recovery")
    parser.add_argument("--duration-seconds", type=float, default=120)
    parser.add_argument("--target-rate", type=float, default=50)
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("docs/acceptance/multiworker-local.json"),
    )
    parser.add_argument(
        "--workload-output",
        type=Path,
        default=Path("docs/benchmarks/multiworker-recovery-workload-local.json"),
    )
    args = parser.parse_args()
    report = run_acceptance(
        duration_seconds=args.duration_seconds,
        target_rate=args.target_rate,
        output=args.output,
        workload_output=args.workload_output,
    )
    print(json.dumps(report, indent=2))
    if not cast(dict[str, Any], report["verdict"])["passed"]:
        raise SystemExit(2)


if __name__ == "__main__":
    main()
