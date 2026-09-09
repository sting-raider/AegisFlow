from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from apps.api import main
from packages.model_bundle import BundleError


def test_model_load_failure_does_not_train_implicitly(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    calls = 0

    def fail(_registry: Path) -> Any:
        nonlocal calls
        calls += 1
        raise BundleError("missing")

    monkeypatch.delenv("AEGISFLOW_ALLOW_STARTUP_MODEL_TRAINING", raising=False)
    monkeypatch.setattr(main, "load_production_bundle", fail)

    with pytest.raises(BundleError, match="missing"):
        main._load_runtime_bundle(tmp_path)
    assert calls == 1


def test_explicit_startup_training_retries_bundle_once(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    from training.cli import train_smoke

    bundle = SimpleNamespace(manifest={"version": "test"})
    attempts = 0
    trained = False

    def load(_registry: Path) -> Any:
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            raise BundleError("missing")
        return bundle

    def train(registry: Path) -> None:
        nonlocal trained
        assert registry == tmp_path
        trained = True

    monkeypatch.setenv("AEGISFLOW_ALLOW_STARTUP_MODEL_TRAINING", "1")
    monkeypatch.setattr(main, "load_production_bundle", load)
    monkeypatch.setattr(train_smoke, "train", train)

    assert main._load_runtime_bundle(tmp_path) is bundle
    assert trained is True
    assert attempts == 2
