# AegisFlow autonomous engineering guide

Continue implementation without nonessential approval questions. Choose the simplest
maintainable option, record consequential decisions in `docs/DECISIONS.md`, and keep
`docs/PROGRESS.md` honest.

Safety invariants:

- Demo/PCAP replay is the default. Live capture requires an explicit Linux interface.
- Never scan or replay traffic against an external system.
- Never store packet payloads or secrets.
- Detection never triggers automatic blocking.
- Malformed or schema-incompatible events become visible processing errors, never benign.
- Suspicious traffic never enters the benign baseline automatically.
- AI explanations are optional and cannot affect detection.

Common commands:

```text
make install
make lint
make typecheck
make test
make train-smoke
make demo
make demo-stop
make replay PCAP=/path/to/file.pcap
make live INTERFACE=eth0
make benchmark
make reset
```

Python code lives in `packages/`, `services/`, `apps/api/`, and `training/`.
The React/Vite dashboard lives in `apps/dashboard/`. Do not commit large PCAPs,
datasets, databases, or unreviewed model artifacts.
