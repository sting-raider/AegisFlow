from __future__ import annotations

from scripts.benchmark_sustained import assess_sustainability, queue_growth_per_second


def test_queue_growth_uses_final_half_of_ingress_samples() -> None:
    samples = [
        {"elapsed_seconds": float(index), "depth": float(index * 2)}
        for index in range(8)
    ]

    assert queue_growth_per_second(samples, "depth") == 2.0


def test_sustainability_passes_only_with_exact_durability_and_steady_state() -> None:
    result = assess_sustainability(
        planned=1_000,
        published=1_000,
        persisted_flows=1_000,
        persisted_detections=1_000,
        achieved_rate=100.0,
        target_rate=100.0,
        latency_p95_ms=900.0,
        latency_budget_ms=1_000.0,
        final_flow_depth=0,
        final_detection_depth=0,
        maximum_flow_depth=50,
        maximum_detection_depth=40,
        queue_depth_budget=100,
        flow_growth_per_second=0.1,
        detection_growth_per_second=-0.2,
        growth_tolerance_per_second=0.5,
    )

    assert result["sustainable"] is True
    assert all(result["criteria"].values())


def test_sustainability_fails_growing_queue_and_missing_rows() -> None:
    result = assess_sustainability(
        planned=1_000,
        published=1_000,
        persisted_flows=999,
        persisted_detections=998,
        achieved_rate=100.0,
        target_rate=100.0,
        latency_p95_ms=900.0,
        latency_budget_ms=1_000.0,
        final_flow_depth=1,
        final_detection_depth=2,
        maximum_flow_depth=90,
        maximum_detection_depth=80,
        queue_depth_budget=100,
        flow_growth_per_second=3.0,
        detection_growth_per_second=2.0,
        growth_tolerance_per_second=0.5,
    )

    assert result["sustainable"] is False
    assert result["criteria"]["no_unexplained_loss"] is False
    assert result["criteria"]["queue_depth_bounded"] is False
    assert result["criteria"]["returned_to_steady_state"] is False


def test_sustainability_fails_rate_latency_and_queue_budget() -> None:
    result = assess_sustainability(
        planned=1_000,
        published=1_000,
        persisted_flows=1_000,
        persisted_detections=1_000,
        achieved_rate=97.9,
        target_rate=100.0,
        latency_p95_ms=1_001.0,
        latency_budget_ms=1_000.0,
        final_flow_depth=0,
        final_detection_depth=0,
        maximum_flow_depth=101,
        maximum_detection_depth=100,
        queue_depth_budget=100,
        flow_growth_per_second=0.0,
        detection_growth_per_second=0.0,
        growth_tolerance_per_second=0.5,
    )

    assert result["sustainable"] is False
    assert result["criteria"]["input_rate_maintained"] is False
    assert result["criteria"]["latency_within_budget"] is False
    assert result["criteria"]["queue_depth_bounded"] is False
