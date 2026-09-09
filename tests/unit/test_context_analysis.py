from __future__ import annotations

from copy import deepcopy
from pathlib import Path

import numpy as np
import pytest

from training.v2.context_analysis import CONTROLS, paired_analysis
from training.v2.context_runner import CaseExecution, PairedSignals
from training.v2.registered_context import load_registration


def _signal(value: bool, benign: bool = False) -> PairedSignals:
    return PairedSignals(
        target_event_ids=tuple(f"attack-{index}" for index in range(8)),
        benign_event_ids=tuple(f"benign-{index}" for index in range(8)),
        target_attack_direct=np.full(8, value),
        target_attack_or_review=np.full(8, value),
        independent_benign_direct=np.full(8, benign),
    )


def _executions(*, benefit: bool) -> tuple[list[CaseExecution], dict]:
    config = deepcopy(load_registration(Path(__file__).resolve().parents[2]))
    config["paired_analysis"]["bootstrap_replicates"] = 50
    executions = []
    number = 0
    for target in config["splits"]["attack_environments"]:
        other = [source for source in config["splits"]["attack_environments"] if source != target]
        for sources in ([other[0]], [other[1]], other):
            for view in config["representation"]["views"]:
                number += 1
                value = view == "causal_context" and benefit
                executions.append(
                    CaseExecution(
                        report={
                            "case_id": f"case-{number}",
                            "target_capture": target,
                            "fit_sources": sources,
                            "view": view,
                            "status": "evaluated",
                        },
                        paired_signals=(_signal(value), _signal(value)),
                    )
                )
    return executions, config


def test_paired_analysis_detects_consistent_registered_benefit() -> None:
    executions, config = _executions(benefit=True)
    result = paired_analysis(executions, config)

    assert result["benefit_detected"] is True
    assert len(result["strata"]) == 12
    assert set(result["control_decisions"]) == set(CONTROLS)
    assert all(item["benefit_qualifying"] for item in result["strata"])
    assert all(
        item["endpoints"]["target_attack_direct"]["paired_bootstrap_95"] == [1.0, 1.0]
        for item in result["strata"]
    )


def test_paired_analysis_returns_registered_null_for_ties() -> None:
    executions, config = _executions(benefit=False)
    result = paired_analysis(executions, config)

    assert result["benefit_detected"] is False
    assert result["scientific_conclusion"].startswith("null_")
    assert not any(item["benefit_qualifying"] for item in result["strata"])


def test_paired_analysis_rejects_unpaired_event_ids() -> None:
    executions, config = _executions(benefit=True)
    target = executions[0]
    original = target.paired_signals[0]
    changed = PairedSignals(
        target_event_ids=("different", *original.target_event_ids[1:]),
        benign_event_ids=original.benign_event_ids,
        target_attack_direct=original.target_attack_direct,
        target_attack_or_review=original.target_attack_or_review,
        independent_benign_direct=original.independent_benign_direct,
    )
    executions[0] = CaseExecution(target.report, (changed, target.paired_signals[1]))

    with pytest.raises(ValueError, match="event IDs differ"):
        paired_analysis(executions, config)
