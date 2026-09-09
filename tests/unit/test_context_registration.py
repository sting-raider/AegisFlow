from __future__ import annotations

from copy import deepcopy
from pathlib import Path

import pytest

from training.v2.registered_context import load_registration, validate_registration


def test_context_registration_is_bound_and_development_only() -> None:
    root = Path(__file__).resolve().parents[2]
    config = load_registration(root)

    assert config["status"] == "registered_not_run"
    assert config["permitted_use"] == "development_only"
    assert config["candidate_promotion_authorized"] is False
    assert config["splits"]["expected_model_fits"] == 36
    assert config["splits"]["expected_site_evaluations"] == 72


def test_context_registration_rejects_representation_mutation() -> None:
    root = Path(__file__).resolve().parents[2]
    config = deepcopy(load_registration(root))
    config["representation"]["sequence_consumed"] = True

    with pytest.raises(ValueError, match="representation contract changed"):
        validate_registration(root, config)


def test_context_registration_rejects_benefit_rule_mutation() -> None:
    root = Path(__file__).resolve().parents[2]
    config = deepcopy(load_registration(root))
    config["paired_analysis"]["benefit_minimum_positive_strata_per_control"] = 1

    with pytest.raises(ValueError, match="paired-analysis rule changed"):
        validate_registration(root, config)

