from __future__ import annotations

import json

from apps.api.database import Repository
from apps.api.retention import retention_worker_from_env


def main() -> None:
    repository = Repository()
    repository.create_schema()
    worker = retention_worker_from_env(repository)
    if worker is None:
        raise SystemExit("retention cleanup is disabled")
    print(json.dumps(worker.run_once(), sort_keys=True))


if __name__ == "__main__":
    main()
