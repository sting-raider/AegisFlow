from pathlib import Path


def main() -> None:
    target = Path("aegisflow-demo.db").resolve()
    if target.parent != Path.cwd().resolve():
        raise RuntimeError("refusing to remove database outside workspace")
    if target.exists():
        target.unlink()
        print(f"Removed {target}; it cannot be recovered.")
    else:
        print("No local demo database exists.")


if __name__ == "__main__":
    main()
