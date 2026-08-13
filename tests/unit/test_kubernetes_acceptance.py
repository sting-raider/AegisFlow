from scripts.accept_kubernetes import assess_counts


def test_assess_counts_accepts_exact_demo_conservation() -> None:
    assert assess_counts({"flows": 6, "detections": 6, "alerts": 5, "incidents": 1}) == []


def test_assess_counts_rejects_loss_and_duplicates() -> None:
    failures = assess_counts({"flows": 5, "detections": 7, "alerts": 5, "incidents": 1})
    assert failures == [
        "flows count was 5, expected 6",
        "detections count was 7, expected 6",
    ]
