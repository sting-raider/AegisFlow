# Master plan

## Final acceptance plan (authoritative from 2026-08-10)

The earlier implementation phases remain useful engineering evidence, but their stop
condition has been superseded. Completion now requires either a promoted production
candidate that passes the locked scientific and operational gates, or an evidence-backed
scientific NO-GO with the engineering platform explicitly separated from detector quality.

| Phase | Deliverable | Status |
|---|---|---|
| A0 | Freeze legacy final evidence and prevent development use | Complete; automated guard green |
| A1 | Audit feature portability; implement portable and bounded temporal schemas with parity | Complete for research: full Schema A blocked by origin diagnostic; numerical-core ablation remains eligible |
| A2 | Acquire and provenance a fresh non-frozen development corpus | Complete for initial experiments: three official environments, six temporal IoT captures, frozen boundary green |
| A3 | Register baselines/challengers; run cost, ablation, held-family and cross-environment development experiments | Complete for current family; DEV-CAL-001 fails final predeclared development test |
| A4 | Lock one challenger; run frozen final evidence once; issue scientific GO/NO-GO | Development NO-GO: no eligible challenger to lock; frozen evidence remains sealed |
| A5 | Sustained/burst/failure performance and multi-worker correctness acceptance | In progress; 10-minute point and local multi-worker recovery pass, 30-minute 50 flows/s capacity point fails, lower-rate ladder/failures open |
| A6 | Real local OIDC, Kubernetes, restore, rollout/failure and security drills | In progress; disposable real OIDC and local PostgreSQL restore pass; Kubernetes/security remain open |
| A7 | Production validator, release provenance, operator package and final acceptance report | In progress; preflight and operator package complete; release provenance/final report open |

The four reports listed in `configs/evaluation/frozen-evidence-v1.json` are final-only.
They cannot be used to choose A1-A4 features, models, hyperparameters, thresholds, or
calibration.

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
