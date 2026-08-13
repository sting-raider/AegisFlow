from pathlib import Path

from scripts.accept_kubernetes import _safe_command, _uids_replaced, assess_counts


def test_assess_counts_accepts_exact_demo_conservation() -> None:
    assert assess_counts({"flows": 6, "detections": 6, "alerts": 5, "incidents": 1}) == []


def test_assess_counts_rejects_loss_and_duplicates() -> None:
    failures = assess_counts({"flows": 5, "detections": 7, "alerts": 5, "incidents": 1})
    assert failures == [
        "flows count was 5, expected 6",
        "detections count was 7, expected 6",
    ]


def test_safe_command_redacts_disposable_secrets() -> None:
    rendered = _safe_command(
        [
            "kubectl",
            "--from-literal=POSTGRES_PASSWORD=aegisflow-kind-only",
            "--from-literal=AEGISFLOW_DATABASE_URL=postgresql+psycopg://secret",
        ]
    )
    assert "aegisflow-kind-only" not in rendered
    assert "psycopg" not in rendered
    assert rendered.count("<redacted>") == 2


def test_nonroot_postgres_initializes_below_the_volume_mount() -> None:
    manifest = Path("infra/kubernetes-local-acceptance/stateful.yaml").read_text(
        encoding="utf-8"
    )
    assert "PGDATA, value: /var/lib/postgresql/data/pgdata" in manifest


def test_nonroot_model_seed_does_not_preserve_pvc_root_metadata() -> None:
    manifest = Path("infra/kubernetes/acceptance/model-seed-job.yaml").read_text(
        encoding="utf-8"
    )
    assert "cp -a" not in manifest
    assert "cp -R /app/models/registry/* /models/" in manifest


def test_uid_replacement_requires_a_nonempty_disjoint_pod_set() -> None:
    previous = {"old-a", "old-b"}

    assert not _uids_replaced(previous, [])
    assert not _uids_replaced(previous, [{"name": "terminating", "uid": "old-a"}])
    assert _uids_replaced(previous, [{"name": "ready", "uid": "new-a"}])
