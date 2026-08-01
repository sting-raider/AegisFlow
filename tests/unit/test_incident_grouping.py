from __future__ import annotations

import pytest

from packages.incidents.grouping import (
    AlertGroupingContext,
    IncidentGroupingContext,
    attack_stage,
    grouping_reasons,
    should_group,
)


def existing_context() -> IncidentGroupingContext:
    return IncidentGroupingContext(
        source_hosts=frozenset({"source-a"}),
        destination_hosts=frozenset({"destination-a"}),
        signature_ids=frozenset({"signature-a"}),
        reason_codes=frozenset({"PORT_SWEEP"}),
        attack_stages=frozenset({"reconnaissance"}),
        severities=("low", "medium"),
        risks=(20.0, 40.0),
    )


def new_context(**changes: object) -> AlertGroupingContext:
    values: dict[str, object] = {
        "source_host": "source-b",
        "destination_host": "destination-b",
        "signature_ids": frozenset({"signature-b"}),
        "reason_codes": frozenset({"OTHER"}),
        "attack_stage": "credential_access",
        "severity": "medium",
        "risk": 35.0,
    }
    values.update(changes)
    return AlertGroupingContext(**values)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("changes", "expected"),
    [
        ({"source_host": "source-a"}, "same source host"),
        ({"destination_host": "destination-a"}, "shared destination"),
        ({"signature_ids": frozenset({"signature-a"})}, "common signature"),
        ({"reason_codes": frozenset({"PORT_SWEEP"})}, "common reason"),
        ({"attack_stage": "reconnaissance"}, "similar attack stage (reconnaissance)"),
        ({"severity": "high", "risk": 60.0}, "repeated escalation"),
    ],
)
def test_every_required_incident_rule_is_explainable(
    changes: dict[str, object], expected: str
) -> None:
    reasons = grouping_reasons(existing_context(), new_context(**changes))
    assert reasons[0] == "time proximity"
    assert expected in reasons
    assert should_group(reasons)


def test_time_proximity_and_generic_stage_are_not_enough() -> None:
    reasons = grouping_reasons(
        IncidentGroupingContext(
            source_hosts=frozenset({"a"}),
            destination_hosts=frozenset({"b"}),
            signature_ids=frozenset(),
            reason_codes=frozenset(),
            attack_stages=frozenset({"unclassified_anomaly"}),
            severities=("low",),
            risks=(20.0,),
        ),
        new_context(attack_stage="unclassified_anomaly"),
    )
    assert reasons == ("time proximity",)
    assert not should_group(reasons)


@pytest.mark.parametrize(
    ("evidence", "expected"),
    [
        ({"reason_codes": {"PORT_SWEEP"}}, "reconnaissance"),
        ({"reason_codes": {"REPEATED_AUTH_FAILURE"}}, "credential_access"),
        ({"reason_codes": {"LARGE_OUTBOUND_TRANSFER"}}, "exfiltration"),
        ({"signature_name": "possible C2 beacon"}, "command_and_control"),
        ({"signature_category": "attempted exploit"}, "execution"),
        ({"signature_category": "denial of service"}, "impact"),
    ],
)
def test_attack_stage_mapping_is_deterministic(
    evidence: dict[str, object], expected: str
) -> None:
    assert attack_stage(**evidence) == expected  # type: ignore[arg-type]
