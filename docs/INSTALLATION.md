# Installation

## Supported paths

Use Docker Desktop or Docker Engine with Compose for the reproducible demo. Python 3.11,
Node 22, `uv`, GNU Make, and `kubectl` are required only for development and deployment
validation. Windows supports demo and PCAP replay; live capture is Linux-only.

Clone the public repository and verify the checkout before running code:

```bash
git clone https://github.com/sting-raider/AegisFlow.git
cd AegisFlow
git status --short
docker version
docker compose version
```

Do not place PCAPs, datasets, secrets, database dumps, or unreviewed model artifacts in
the repository. Confirm the host has enough disk for the backend image and at least 4 GiB
of memory available to Docker.

## Demo installation

```bash
make demo
```

This builds local images, trains/checks the synthetic smoke bundle, migrates a local
PostgreSQL database, starts loopback-only services, and replays safe synthetic metadata.
Open `http://127.0.0.1:5173`; stop with `make demo-stop`.

Verify readiness and counts:

```bash
curl --fail http://127.0.0.1:8000/health/ready
curl --fail http://127.0.0.1:8000/api/v1/system/status
```

The expected first demo has 6 flows, 6 detections, 5 alerts, and 1 incident. Repeating
the replay must not increase those deterministic counts.

## Development installation

```bash
make install
make lint
make typecheck
make test
make frozen-evidence-check
make research-evidence-check
```

Dependency resolution is locked by `uv.lock` and the dashboard `package-lock.json`.
Installation success is not detector-quality or production-acceptance evidence.

## Production boundary

Read [`CONFIGURATION.md`](CONFIGURATION.md), [`DEPLOYMENT.md`](DEPLOYMENT.md), and
[`SECURITY.md`](SECURITY.md), then run `make production-check`. The checked-in smoke model
is deliberately rejected, so default production preflight must fail. Do not weaken the
validator to make that result green.
