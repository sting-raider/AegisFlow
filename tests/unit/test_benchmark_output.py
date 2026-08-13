from pathlib import Path

import pytest

from scripts.prepare_benchmark_output import prepare_output


def test_prepare_output_creates_only_the_requested_json_file(tmp_path: Path) -> None:
    output = prepare_output(tmp_path / "benchmarks", "sustained.json")

    assert output == tmp_path / "benchmarks" / "sustained.json"
    assert output.read_text(encoding="utf-8") == ""
    assert output.stat().st_mode & 0o666 == 0o666


@pytest.mark.parametrize(
    "name",
    ["", ".", "..", "../outside.json", "nested/report.json", "nested\\report.json", "report.txt"],
)
def test_prepare_output_rejects_paths_and_non_json_names(tmp_path: Path, name: str) -> None:
    with pytest.raises(ValueError, match="JSON filename"):
        prepare_output(tmp_path, name)
