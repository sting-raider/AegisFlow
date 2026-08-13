from scripts.accept_kubernetes import _safe_command, assess_counts


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
