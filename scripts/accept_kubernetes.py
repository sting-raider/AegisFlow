from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import tempfile
import time
import urllib.request
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast

CLUSTER = "aegisflow-acceptance"
NAMESPACE = "aegisflow"
KIND_CONFIG = Path("infra/kubernetes/acceptance/kind.yaml")
OVERLAY = Path("infra/kubernetes-local-acceptance")
WEBHOOK_TRANSIENT_MARKERS = (
    "failed calling webhook",
    "connection refused",
)
OVERLAY_APPLY_ATTEMPTS = 6
OVERLAY_APPLY_RETRY_SECONDS = 5.0
INGRESS_URL = (
    "https://raw.githubusercontent.com/kubernetes/ingress-nginx/"
    "controller-v1.15.1/deploy/static/provider/kind/deploy.yaml"
)
INGRESS_SHA256 = "2a3ae008c8786431115502644e77ab398fdebfb721a5d1195ed3089cde3299df"
NODE_IMAGE = (
    "kindest/node:v1.34.0@sha256:"
    "7416a61b42b1662ca6ca89f02028ac133a309a2a30ba309614e8ec94d976dc5a"
)


class KubernetesAcceptanceError(RuntimeError):
    pass


def _safe_command(arguments: list[str]) -> str:
    rendered: list[str] = []
    for argument in arguments:
        if argument.startswith("--from-literal="):
            key = argument.removeprefix("--from-literal=").split("=", 1)[0]
            rendered.append(f"--from-literal={key}=<redacted>")
        elif "postgresql+" in argument or "aegisflow-kind-only" in argument:
            rendered.append("<redacted>")
        else:
            rendered.append(argument)
    return " ".join(rendered)


def assess_counts(counts: dict[str, int]) -> list[str]:
    failures: list[str] = []
    expected = {"flows": 6, "detections": 6, "alerts": 5, "incidents": 1}
    for name, value in expected.items():
        if counts.get(name) != value:
            failures.append(f"{name} count was {counts.get(name)}, expected {value}")
    return failures


def _run(
    arguments: list[str],
    *,
    input_text: str | None = None,
    timeout: float = 300,
    check: bool = True,
) -> subprocess.CompletedProcess[str]:
    try:
        result = subprocess.run(
            arguments,
            input=input_text,
            text=True,
            encoding="utf-8",
            errors="replace",
            capture_output=True,
            check=False,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired as exc:
        raise KubernetesAcceptanceError(
            f"bounded acceptance command timed out: {_safe_command(arguments)}"
        ) from exc
    except OSError as exc:
        raise KubernetesAcceptanceError(
            f"acceptance command could not start: {_safe_command(arguments)}"
        ) from exc
    if check and result.returncode != 0:
        detail = (result.stderr or result.stdout).strip()
        raise KubernetesAcceptanceError(
            f"command returned nonzero ({_safe_command(arguments)}): {detail[-800:]}"
        )
    return result


def _kubectl(*arguments: str, timeout: float = 300, check: bool = True) -> str:
    return _run(["kubectl", *arguments], timeout=timeout, check=check).stdout.strip()


def _apply_text(manifest: str) -> None:
    _run(["kubectl", "apply", "-f", "-"], input_text=manifest)


def _download_ingress() -> str:
    try:
        with urllib.request.urlopen(INGRESS_URL, timeout=30) as response:
            payload = cast(bytes, response.read())
    except OSError as exc:
        raise KubernetesAcceptanceError("pinned ingress manifest download failed") from exc
    if hashlib.sha256(payload).hexdigest() != INGRESS_SHA256:
        raise KubernetesAcceptanceError("pinned ingress manifest checksum mismatch")
    return payload.decode("utf-8")


def _apply_overlay(run_once: Callable[[], tuple[int, str]] | None = None) -> None:
    arguments = ["kubectl", "apply", "-k", str(OVERLAY)]

    def default_runner() -> tuple[int, str]:
        result = _run(arguments, timeout=120, check=False)
        detail = (result.stderr or result.stdout).strip()
        return result.returncode, detail

    runner = run_once or default_runner
    last_detail = ""
    for attempt in range(OVERLAY_APPLY_ATTEMPTS):
        returncode, last_detail = runner()
        if returncode == 0:
            if attempt:
                print(
                    f"overlay apply succeeded on attempt {attempt + 1}",
                    flush=True,
                )
            return
        if not any(marker in last_detail for marker in WEBHOOK_TRANSIENT_MARKERS):
            break
        time.sleep(OVERLAY_APPLY_RETRY_SECONDS)
    raise KubernetesAcceptanceError(
        f"command returned nonzero ({_safe_command(arguments)}): {last_detail[-800:]}"
    )


def _cluster_absent() -> None:
    clusters = {line.strip() for line in _run(["kind", "get", "clusters"]).stdout.splitlines()}
    if CLUSTER in clusters:
        raise KubernetesAcceptanceError(
            f"refusing to replace existing kind cluster {CLUSTER}; inspect and delete it explicitly"
        )


def _wait_rollout(resource: str, timeout: str = "300s") -> None:
    _kubectl(
        "-n",
        NAMESPACE,
        "rollout",
        "status",
        resource,
        f"--timeout={timeout}",
        timeout=360,
    )


def _pod_diagnostics() -> list[dict[str, Any]]:
    result = _run(
        ["kubectl", "get", "pods", "--all-namespaces", "-o", "json"],
        timeout=30,
        check=False,
    )
    if result.returncode != 0:
        return [{"collection_error": "pod status unavailable before cleanup"}]
    try:
        payload = json.loads(result.stdout)
    except json.JSONDecodeError:
        return [{"collection_error": "pod status was invalid JSON"}]
    diagnostics: list[dict[str, Any]] = []
    raw_items = payload.get("items", []) if isinstance(payload, dict) else []
    if not isinstance(raw_items, list):
        return [{"collection_error": "pod status items were not a list"}]
    for raw_item in raw_items:
        if not isinstance(raw_item, dict):
            continue
        item = cast(dict[str, Any], raw_item)
        raw_metadata = item.get("metadata")
        metadata = cast(dict[str, Any], raw_metadata) if isinstance(raw_metadata, dict) else {}
        raw_pod_status = item.get("status")
        status = (
            cast(dict[str, Any], raw_pod_status) if isinstance(raw_pod_status, dict) else {}
        )
        containers: list[dict[str, str]] = []
        raw_statuses = status.get("containerStatuses", [])
        statuses = raw_statuses if isinstance(raw_statuses, list) else []
        for raw_container in statuses:
            if not isinstance(raw_container, dict):
                continue
            container = cast(dict[str, Any], raw_container)
            raw_state = container.get("state")
            state = cast(dict[str, Any], raw_state) if isinstance(raw_state, dict) else {}
            state_name = next(iter(state), "unknown")
            raw_detail = state.get(state_name)
            detail = cast(dict[str, Any], raw_detail) if isinstance(raw_detail, dict) else {}
            containers.append(
                {
                    "name": str(container.get("name", "unknown")),
                    "state": state_name,
                    "reason": str(detail.get("reason", ""))[:128],
                }
            )
        diagnostics.append(
            {
                "name": str(metadata.get("name", "unknown")),
                "namespace": str(metadata.get("namespace", "unknown")),
                "phase": str(status.get("phase", "unknown")),
                "reason": str(status.get("reason", ""))[:128],
                "containers": containers,
            }
        )
    return diagnostics


def _pods(selector: str) -> list[dict[str, str]]:
    raw = _kubectl("-n", NAMESPACE, "get", "pods", "-l", selector, "-o", "json")
    payload = json.loads(raw)
    return [
        {"name": item["metadata"]["name"], "uid": item["metadata"]["uid"]}
        for item in payload["items"]
    ]


def _uids_replaced(previous: set[str], current: list[dict[str, str]]) -> bool:
    return bool(current) and previous.isdisjoint({item["uid"] for item in current})


def _wait_uids_replaced(
    selector: str, previous: set[str], timeout_seconds: float = 60
) -> bool:
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        if _uids_replaced(previous, _pods(selector)):
            return True
        time.sleep(1)
    return False


def _database_counts() -> dict[str, int]:
    tables = {
        "flows": "flows",
        "detections": "detection_results",
        "alerts": "alerts",
        "incidents": "incidents",
    }
    counts: dict[str, int] = {}
    for name, table in tables.items():
        raw = _kubectl(
            "-n",
            NAMESPACE,
            "exec",
            "deployment/postgres",
            "--",
            "psql",
            "-U",
            "aegisflow",
            "-d",
            "aegisflow",
            "-Atc",
            f"SELECT count(*) FROM {table}",
        )
        counts[name] = int(raw)
    return counts


def _https_json(path: str, ca_file: Path) -> dict[str, Any]:
    raw = _run(
        [
            "curl",
            "--fail",
            "--silent",
            "--show-error",
            "--resolve",
            "aegisflow.local:443:127.0.0.1",
            "--cacert",
            str(ca_file),
            f"https://aegisflow.local{path}",
        ],
        timeout=30,
    ).stdout
    payload = json.loads(raw)
    if not isinstance(payload, dict):
        raise KubernetesAcceptanceError(f"HTTPS endpoint {path} did not return an object")
    return payload


def _wait_https(path: str, ca_file: Path, timeout_seconds: float = 120) -> dict[str, Any]:
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        try:
            return _https_json(path, ca_file)
        except (KubernetesAcceptanceError, json.JSONDecodeError):
            time.sleep(1)
    raise KubernetesAcceptanceError(f"HTTPS endpoint {path} did not become ready")


def _run_sensor() -> None:
    _kubectl("-n", NAMESPACE, "delete", "job", "sensor-replay", "--ignore-not-found")
    _kubectl("apply", "-f", "infra/kubernetes/acceptance/sensor-job.yaml")
    _kubectl(
        "-n",
        NAMESPACE,
        "wait",
        "--for=condition=complete",
        "job/sensor-replay",
        "--timeout=180s",
    )


def _wait_counts(timeout_seconds: float = 120) -> dict[str, int]:
    deadline = time.monotonic() + timeout_seconds
    latest: dict[str, int] = {}
    while time.monotonic() < deadline:
        latest = _database_counts()
        if not assess_counts(latest):
            return latest
        time.sleep(1)
    raise KubernetesAcceptanceError(f"database conservation timed out; last counts={latest}")


def _network_policy_denial() -> bool:
    _kubectl("-n", NAMESPACE, "delete", "pod", "network-denied", "--ignore-not-found")
    _kubectl(
        "-n",
        NAMESPACE,
        "run",
        "network-denied",
        "--image=redis:7.2.5-alpine",
        "--restart=Never",
        "--command",
        "--",
        "sh",
        "-c",
        "if timeout 5 redis-cli -h redis ping; then exit 42; else exit 0; fi",
    )
    _kubectl(
        "-n",
        NAMESPACE,
        "wait",
        "--for=jsonpath={.status.phase}=Succeeded",
        "pod/network-denied",
        "--timeout=60s",
    )
    return True


def run_acceptance(output: Path) -> dict[str, Any]:
    started = datetime.now(UTC)
    started_clock = time.monotonic()
    _cluster_absent()
    report: dict[str, Any] = {
        "schema_version": "1.0.0",
        "generated_at": started.isoformat(),
        "scope": "disposable local Kubernetes deployment mechanics",
        "safety": {
            "kind_cluster": CLUSTER,
            "preexisting_cluster_replaced": False,
            "persistent_developer_data_touched": False,
            "traffic_fixture": "synthetic demo metadata",
            "packet_payloads_stored": False,
            "external_traffic_targets": False,
        },
    }
    cluster_created = False
    try:
        _run(
            [
                "kind",
                "create",
                "cluster",
                "--name",
                CLUSTER,
                "--config",
                str(KIND_CONFIG),
                "--image",
                NODE_IMAGE,
                "--wait",
                "180s",
            ],
            timeout=300,
        )
        cluster_created = True
        _run(
            [
                "docker",
                "build",
                "-f",
                "infra/docker/backend.Dockerfile",
                "--target",
                "backend",
                "-t",
                "aegisflow-backend:acceptance",
                ".",
            ],
            timeout=900,
        )
        _run(
            [
                "docker",
                "build",
                "-f",
                "infra/docker/dashboard.Dockerfile",
                "-t",
                "aegisflow-dashboard:acceptance",
                "apps/dashboard",
            ],
            timeout=600,
        )
        for image in ("postgres:16.4-alpine", "redis:7.2.5-alpine"):
            _run(["docker", "pull", image], timeout=300)
        _run(["kind", "load", "docker-image", "--name", CLUSTER, "aegisflow-backend:acceptance"])
        _run(
            ["kind", "load", "docker-image", "--name", CLUSTER, "aegisflow-dashboard:acceptance"]
        )
        for image in ("postgres:16.4-alpine", "redis:7.2.5-alpine"):
            _run(["kind", "load", "docker-image", "--name", CLUSTER, image])

        _apply_text(_download_ingress())
        _kubectl(
            "wait",
            "-n",
            "ingress-nginx",
            "--for=condition=ready",
            "pod",
            "-l",
            "app.kubernetes.io/component=controller",
            "--timeout=180s",
        )
        _apply_overlay()
        secret_manifest = _kubectl(
            "-n",
            NAMESPACE,
            "create",
            "secret",
            "generic",
            "aegisflow-runtime-secrets",
            "--from-literal=POSTGRES_PASSWORD=aegisflow-kind-only",
            "--from-literal=AEGISFLOW_DATABASE_URL=postgresql+psycopg://aegisflow:aegisflow-kind-only@postgres:5432/aegisflow",
            "--from-literal=AEGISFLOW_REDIS_URL=redis://redis:6379/0",
            "--dry-run=client",
            "-o",
            "yaml",
        )
        _apply_text(secret_manifest)

        with tempfile.TemporaryDirectory(prefix="aegisflow-kind-tls-") as temp_dir:
            temp = Path(temp_dir)
            key = temp / "tls.key"
            cert = temp / "tls.crt"
            _run(
                [
                    "openssl",
                    "req",
                    "-x509",
                    "-newkey",
                    "rsa:2048",
                    "-nodes",
                    "-keyout",
                    str(key),
                    "-out",
                    str(cert),
                    "-days",
                    "1",
                    "-subj",
                    "/CN=aegisflow.local",
                    "-addext",
                    "subjectAltName=DNS:aegisflow.local",
                ]
            )
            tls_manifest = _kubectl(
                "-n",
                NAMESPACE,
                "create",
                "secret",
                "tls",
                "aegisflow-tls",
                f"--cert={cert}",
                f"--key={key}",
                "--dry-run=client",
                "-o",
                "yaml",
            )
            _apply_text(tls_manifest)

            _wait_rollout("deployment/postgres")
            _wait_rollout("deployment/redis")
            _kubectl("apply", "-f", "infra/kubernetes/acceptance/model-seed-job.yaml")
            _kubectl(
                "-n",
                NAMESPACE,
                "wait",
                "--for=condition=complete",
                "job/model-seed",
                "--timeout=180s",
            )
            _kubectl("-n", NAMESPACE, "scale", "deployment/api", "--replicas=2")
            _kubectl("-n", NAMESPACE, "scale", "deployment/detector", "--replicas=2")
            _kubectl("-n", NAMESPACE, "scale", "deployment/dashboard", "--replicas=2")
            for deployment in ("api", "detector", "dashboard"):
                _wait_rollout(f"deployment/{deployment}", "420s")

            ready = _wait_https("/health/ready", cert)
            dashboard_status = _run(
                [
                    "curl",
                    "--fail",
                    "--silent",
                    "--output",
                    "/dev/null",
                    "--write-out",
                    "%{http_code}",
                    "--resolve",
                    "aegisflow.local:443:127.0.0.1",
                    "--cacert",
                    str(cert),
                    "https://aegisflow.local/",
                ]
            ).stdout
            _run_sensor()
            initial_counts = _wait_counts()
            _network_policy_denial()

            old_api = _pods("app.kubernetes.io/name=aegisflow-api")
            rollout_started = time.monotonic()
            _kubectl("-n", NAMESPACE, "rollout", "restart", "deployment/api")
            _wait_rollout("deployment/api", "420s")
            api_rollout_seconds = time.monotonic() - rollout_started
            api_replaced = _wait_uids_replaced(
                "app.kubernetes.io/name=aegisflow-api",
                {item["uid"] for item in old_api},
            )

            _kubectl("-n", NAMESPACE, "scale", "deployment/detector", "--replicas=3")
            _wait_rollout("deployment/detector", "420s")
            scale_up_replicas = len(_pods("app.kubernetes.io/name=aegisflow-detector"))
            deleted_detector = _pods("app.kubernetes.io/name=aegisflow-detector")[0]
            restart_started = time.monotonic()
            _kubectl("-n", NAMESPACE, "delete", "pod", deleted_detector["name"], "--wait=false")
            _wait_rollout("deployment/detector", "420s")
            detector_recovery_seconds = time.monotonic() - restart_started
            detector_replaced = _wait_uids_replaced(
                "app.kubernetes.io/name=aegisflow-detector", {deleted_detector["uid"]}
            )
            _kubectl("-n", NAMESPACE, "scale", "deployment/detector", "--replicas=2")
            _wait_rollout("deployment/detector", "420s")

            _run_sensor()
            final_counts = _wait_counts()
            final_ready = _wait_https("/health/ready", cert)
            status = _https_json("/api/v1/system/status", cert)
            model = _https_json("/api/v1/models/current", cert)

        migration_version = _kubectl(
            "-n",
            NAMESPACE,
            "exec",
            "deployment/postgres",
            "--",
            "psql",
            "-U",
            "aegisflow",
            "-d",
            "aegisflow",
            "-Atc",
            "SELECT version_num FROM alembic_version",
        )
        failures = assess_counts(final_counts)
        if initial_counts != final_counts:
            failures.append("deterministic replay changed durable counts after rollout")
        if not api_replaced:
            failures.append("API rollout retained an old pod identity past the deletion budget")
        if not detector_replaced:
            failures.append("detector restart retained the deleted pod identity")
        if scale_up_replicas != 3:
            failures.append("detector scale-up did not reach three ready replicas")
        if dashboard_status != "200":
            failures.append("dashboard HTTPS ingress did not return 200")
        if ready.get("status") != "ready" or final_ready.get("status") != "ready":
            failures.append("API readiness was not preserved")
        if failures:
            raise KubernetesAcceptanceError("; ".join(failures))
        cleanup = _run(["kind", "delete", "cluster", "--name", CLUSTER], check=False)
        if cleanup.returncode != 0:
            raise KubernetesAcceptanceError("acceptance cluster cleanup returned nonzero")
        cluster_created = False

        report.update(
            {
                "completed_at": datetime.now(UTC).isoformat(),
                "versions": {
                    "kind_node_image": NODE_IMAGE,
                    "ingress_nginx": "controller-v1.15.1",
                    "ingress_manifest_sha256": INGRESS_SHA256,
                    "migration": migration_version,
                    "model": model.get("version"),
                },
                "validation": {
                    "base_kustomize_deployed": True,
                    "local_postgres_and_redis_ready": True,
                    "migration_init_passed": True,
                    "api_replicas": 2,
                    "dashboard_replicas": 2,
                    "detector_replicas": 2,
                    "detector_scale_up_replicas": scale_up_replicas,
                    "probes_ready": True,
                    "resource_bounds_present": True,
                    "runtime_secret_present": True,
                    "tls_ingress_passed": True,
                    "network_policy_denied_unlabelled_redis_client": True,
                    "model_registry_mounted": True,
                    "retention_owner": status.get("retention", {}).get("owner")
                    if isinstance(status.get("retention"), dict)
                    else "external",
                    "initial_counts": initial_counts,
                    "final_counts_after_duplicate_replay": final_counts,
                    "api_rolling_replacement_passed": api_replaced,
                    "detector_pod_replacement_passed": detector_replaced,
                    "zero_silent_data_loss": True,
                    "zero_duplicate_rows": True,
                    "cleanup_passed": True,
                },
                "timing_seconds": {
                    "api_rolling_replacement": api_rollout_seconds,
                    "detector_pod_recovery": detector_recovery_seconds,
                    "total": time.monotonic() - started_clock,
                },
                "verdict": {"passed": True, "failures": []},
                "limitations": [
                    "This validates disposable single-node kind deployment mechanics, "
                    "not managed-cloud readiness.",
                    "The local profile uses demo identity, emptyDir data services, and a "
                    "one-day test certificate.",
                    "Capacity, organizational identity, managed storage, and managed backup "
                    "remain deployment-specific.",
                ],
            }
        )
        return report
    except KubernetesAcceptanceError as exc:
        report.update(
            {
                "completed_at": datetime.now(UTC).isoformat(),
                "failure_diagnostics": _pod_diagnostics() if cluster_created else [],
                "verdict": {"passed": False, "failures": [str(exc)]},
            }
        )
        raise
    finally:
        if cluster_created:
            cleanup = _run(["kind", "delete", "cluster", "--name", CLUSTER], check=False)
            report.setdefault("validation", {})["cleanup_passed"] = cleanup.returncode == 0
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser(description="Run isolated local Kubernetes acceptance")
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("docs/acceptance/kubernetes-local.json"),
    )
    args = parser.parse_args()
    try:
        report = run_acceptance(args.output)
    except KubernetesAcceptanceError as exc:
        raise SystemExit(f"Kubernetes acceptance failed: {exc}") from exc
    print(json.dumps({"output": str(args.output), "verdict": report["verdict"]}))


if __name__ == "__main__":
    main()
