"""Preregistered paired analysis for DEV2-CONTEXT-001."""

from __future__ import annotations

import hashlib
from collections.abc import Mapping, Sequence
from typing import Any

import numpy as np

from training.v2.context_runner import CaseExecution, PairedSignals

CONTROLS = ("shuffled_context", "no_context")
ENDPOINTS = (
    "target_attack_direct",
    "target_attack_or_review",
    "independent_benign_direct",
)


def matrix_choices(config: Mapping[str, Any]) -> list[tuple[str, list[str]]]:
    environments = config["splits"]["attack_environments"]
    choices: list[tuple[str, list[str]]] = []
    for target in environments:
        other = [source for source in environments if source != target]
        choices.extend((target, sources) for sources in ([other[0]], [other[1]], other))
    if len(choices) != config["splits"]["expected_source_target_choices"]:
        raise ValueError("context source/target matrix size changed")
    return choices


def _seed(base: int, stratum: str, control: str, endpoint: str) -> int:
    digest = hashlib.sha256(f"{stratum}\0{control}\0{endpoint}".encode()).digest()
    return (base + int.from_bytes(digest[:8], "little")) % (2**63)


def _interval(
    causal: np.ndarray,
    control: np.ndarray,
    *,
    replicates: int,
    seed: int,
) -> dict[str, Any]:
    left = np.asarray(causal, dtype=np.float64)
    right = np.asarray(control, dtype=np.float64)
    if (
        left.ndim != 1
        or left.shape != right.shape
        or not len(left)
        or not np.isfinite(left).all()
        or not np.isfinite(right).all()
        or not ((0 <= left) & (left <= 1)).all()
        or not ((0 <= right) & (right <= 1)).all()
        or replicates < 1
    ):
        raise ValueError("paired context endpoint arrays are invalid")
    delta = left - right
    rng = np.random.default_rng(seed)
    indices = rng.integers(0, len(delta), size=(replicates, len(delta)))
    bootstrapped = delta[indices].mean(axis=1)
    low, high = np.quantile(bootstrapped, [0.025, 0.975])
    return {
        "rows": len(delta),
        "fit_choices_averaged_per_row": 3,
        "causal_rate": float(left.mean()),
        "control_rate": float(right.mean()),
        "delta": float(delta.mean()),
        "paired_bootstrap_95": [float(low), float(high)],
        "bootstrap_replicates": replicates,
    }


def _stack(
    signals: Sequence[PairedSignals], field: str, ids_field: str
) -> tuple[tuple[str, ...], np.ndarray]:
    if len(signals) != 3:
        raise ValueError("paired context stratum requires three fit choices")
    event_ids = getattr(signals[0], ids_field)
    if any(getattr(signal, ids_field) != event_ids for signal in signals[1:]):
        raise ValueError("paired context event IDs differ across fit choices")
    arrays = [np.asarray(getattr(signal, field), dtype=np.float64) for signal in signals]
    if any(array.shape != (len(event_ids),) for array in arrays):
        raise ValueError("paired context signals differ from their event IDs")
    return event_ids, np.stack(arrays).mean(axis=0)


def paired_analysis(
    executions: Sequence[CaseExecution], config: Mapping[str, Any]
) -> dict[str, Any]:
    """Apply the locked six-stratum paired bootstrap and benefit rule."""
    choices = matrix_choices(config)
    expected = len(choices) * len(config["representation"]["views"])
    if len(executions) != expected:
        raise ValueError("context execution matrix is incomplete")
    indexed: dict[tuple[str, tuple[str, ...], str], CaseExecution] = {}
    for execution in executions:
        report = execution.report
        key = (
            report["target_capture"],
            tuple(report["fit_sources"]),
            report["view"],
        )
        if key in indexed:
            raise ValueError("duplicate context execution case")
        indexed[key] = execution
    expected_keys = {
        (target, tuple(sources), view)
        for target, sources in choices
        for view in config["representation"]["views"]
    }
    if set(indexed) != expected_keys:
        raise ValueError("context execution cases differ from registered matrix")

    replicates = config["paired_analysis"]["bootstrap_replicates"]
    base_seed = config["execution"]["seed"]
    strata = []
    for target in config["splits"]["attack_environments"]:
        target_choices = [sources for candidate, sources in choices if candidate == target]
        for orientation_index, orientation in enumerate(
            config["splits"]["site_orientations"]
        ):
            stratum_id = f"{target}|orientation-{orientation_index + 1}"
            for control in CONTROLS:
                causal_cases = [
                    indexed[(target, tuple(sources), "causal_context")]
                    for sources in target_choices
                ]
                control_cases = [
                    indexed[(target, tuple(sources), control)]
                    for sources in target_choices
                ]
                cases = [*causal_cases, *control_cases]
                entry: dict[str, Any] = {
                    "stratum_id": stratum_id,
                    "target_capture": target,
                    "orientation": dict(orientation),
                    "control": control,
                    "case_ids": [case.report["case_id"] for case in cases],
                }
                if any(
                    case.report["status"] != "evaluated"
                    or len(case.paired_signals) != 2
                    for case in cases
                ):
                    entry.update(
                        {
                            "status": "unavailable_ineligible_case",
                            "benefit_qualifying": False,
                        }
                    )
                    strata.append(entry)
                    continue
                causal_signals = [case.paired_signals[orientation_index] for case in causal_cases]
                control_signals = [case.paired_signals[orientation_index] for case in control_cases]
                endpoint_values = {}
                specifications = (
                    ("target_attack_direct", "target_event_ids"),
                    ("target_attack_or_review", "target_event_ids"),
                    ("independent_benign_direct", "benign_event_ids"),
                )
                for endpoint, ids_field in specifications:
                    causal_ids, causal_values = _stack(
                        causal_signals, endpoint, ids_field
                    )
                    control_ids, control_values = _stack(
                        control_signals, endpoint, ids_field
                    )
                    if causal_ids != control_ids:
                        raise ValueError("causal/control paired event IDs differ")
                    endpoint_values[endpoint] = _interval(
                        causal_values,
                        control_values,
                        replicates=replicates,
                        seed=_seed(base_seed, stratum_id, control, endpoint),
                    )
                direct_low = endpoint_values["target_attack_direct"][
                    "paired_bootstrap_95"
                ][0]
                review_low = endpoint_values["target_attack_or_review"][
                    "paired_bootstrap_95"
                ][0]
                safety_high = endpoint_values["independent_benign_direct"][
                    "paired_bootstrap_95"
                ][1]
                entry.update(
                    {
                        "status": "evaluated",
                        "endpoints": endpoint_values,
                        "benefit_qualifying": (
                            direct_low > 0
                            and review_low > 0
                            and safety_high
                            <= config["paired_analysis"][
                                "benefit_max_safety_upper_delta"
                            ]
                        ),
                    }
                )
                strata.append(entry)

    expected_strata = config["paired_analysis"]["expected_strata"] * len(CONTROLS)
    if len(strata) != expected_strata:
        raise ValueError("paired context stratum count changed")
    control_decisions = {}
    for control in CONTROLS:
        items = [entry for entry in strata if entry["control"] == control]
        qualified = [entry for entry in items if entry["benefit_qualifying"]]
        targets = {entry["target_capture"] for entry in qualified}
        orientations = {
            (entry["orientation"]["calibration"], entry["orientation"]["benign_test"])
            for entry in qualified
        }
        benefit = (
            len(qualified)
            >= config["paired_analysis"]["benefit_minimum_positive_strata_per_control"]
            and targets == set(config["splits"]["attack_environments"])
            and len(orientations) == len(config["splits"]["site_orientations"])
        )
        control_decisions[control] = {
            "benefit_detected": benefit,
            "qualifying_strata": len(qualified),
            "required_strata": config["paired_analysis"][
                "benefit_minimum_positive_strata_per_control"
            ],
            "all_targets_represented": targets
            == set(config["splits"]["attack_environments"]),
            "all_orientations_represented": len(orientations)
            == len(config["splits"]["site_orientations"]),
        }
    benefit = all(item["benefit_detected"] for item in control_decisions.values())
    return {
        "comparisons": list(config["paired_analysis"]["comparisons"]),
        "terminal_reference_excluded_from_benefit_rule": True,
        "strata": strata,
        "control_decisions": control_decisions,
        "benefit_detected": benefit,
        "scientific_conclusion": (
            "detectable_causal_benefit_under_registered_rule"
            if benefit
            else "null_no_detectable_causal_benefit_under_registered_rule"
        ),
        "interpretation": config["paired_analysis"]["interpretation"],
    }
