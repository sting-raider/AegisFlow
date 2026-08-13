from __future__ import annotations

import argparse
import os
from pathlib import Path


def prepare_output(directory: Path, name: str) -> Path:
    if (
        not name
        or name in {".", ".."}
        or "/" in name
        or "\\" in name
        or Path(name).suffix != ".json"
    ):
        raise ValueError("benchmark output must be a JSON filename without directories")
    directory.mkdir(parents=True, exist_ok=True)
    output = directory / name
    output.write_text("", encoding="utf-8")
    os.chmod(output, 0o666)
    return output


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Prepare one bind-mounted sustained benchmark output file"
    )
    parser.add_argument("--name", required=True)
    parser.add_argument("--directory", type=Path, default=Path("docs/benchmarks"))
    args = parser.parse_args()
    print(prepare_output(args.directory, args.name))


if __name__ == "__main__":
    main()
