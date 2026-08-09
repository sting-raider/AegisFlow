# Master plan

| Phase | Deliverable | Status |
|---|---|---|
| 0 | Upstream audit, attribution, decisions, execution guide | Complete |
| 1 | Contracts, feature registry, persistence, API health, Compose | Complete |
| 2 | Demo flow → detection → database → API → dashboard | Complete |
| 3 | PCAP adapter, live guard, Suricata EVE parser/correlation | Complete |
| 4 | Smoke training, train-only preprocessing, versioned bundle | Complete |
| 5 | Open-set fusion, thresholds, benchmarks | Complete |
| 6 | Incidents, feedback, WebSockets, dashboard pages | Complete |
| 7 | Drift and safe optional explanations | Complete |
| 8 | Malformed-input/recovery tests, threat model, CI scans | Complete |
| 9 | Full validation and final measured status | Complete |

This phase table does not substitute for the authoritative requirement audit. The
requirement-by-requirement evidence is recorded in `docs/COMPLETION_AUDIT.md`.

## Production-readiness expansion

| Phase | Deliverable | Status |
|---|---|---|
| P1 | Gap map and honest claim reset | Complete |
| P2 | Direction semantics, Community ID, exact hybrid evaluation, calibration/fusion | Complete implementation/evidence; current model rejected |
| P3 | Profiling, batching/scaling, resilience and deployment hardening | In progress (single-host performance and deployment templates complete) |
| P4 | Editorial intelligence design system and full dashboard transformation | Complete |
| P5 | Authentication/RBAC, retraining governance and release readiness | Complete as repository implementation; target IdP/cluster validation remains P6 |
| P6 | Real-data, performance, security, UI, deployment and public CI validation | In progress (UI complete; model, scale and target-environment evidence remain) |
