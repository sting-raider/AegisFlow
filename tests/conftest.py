from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import pytest

from packages.model_bundle import ModelBundle
from training.cli.train_smoke import train


@pytest.fixture(scope="session")
def registry(tmp_path_factory: pytest.TempPathFactory) -> Iterator[Path]:
    root = tmp_path_factory.mktemp("registry")
    train(root)
    yield root


@pytest.fixture(scope="session")
def bundle(registry: Path) -> ModelBundle:
    return ModelBundle.load(registry / "aegisflow-smoke" / "0.1.0")
