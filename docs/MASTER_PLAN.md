# Master plan

## Final acceptance plan (authoritative from 2026-08-10; audit reopened 2026-09-02)

Current requirement coverage and unresolved work are in
[REQUIREMENTS_AUDIT.md](REQUIREMENTS_AUDIT.md). Earlier blanket closure claims are superseded.

The earlier implementation phases remain useful engineering evidence, but their stop
condition has been superseded. Completion now requires either a promoted production
candidate that passes the locked scientific and operational gates, or an evidence-backed
scientific NO-GO with the engineering platform explicitly separated from detector quality.

| Phase | Deliverable | Status |
|---|---|---|
| A0 | Freeze legacy final evidence and prevent development use | Complete; automated guard green |
| A1 | Audit feature portability; implement portable and bounded temporal schemas with parity | Complete for research: full Schema A blocked by origin diagnostic; numerical-core ablation remains eligible |
| A2 | Acquire and provenance a fresh non-frozen development corpus | Complete for initial experiments: three official environments, six temporal IoT captures, frozen boundary green |
| A3 | Register baselines/challengers; run cost, ablation, held-family and cross-environment development experiments | V1 retained with DEV-CAL-001 NO-GO; v2 scientific corrections and registered reruns remain |
| A4 | Lock one challenger; run frozen final evidence once; issue scientific GO/NO-GO | Development NO-GO: no eligible challenger to lock; frozen evidence remains sealed |
| A5 | Sustained/burst/failure performance and multi-worker correctness acceptance | Capacity points retained; during-load failure and resharding coverage still requires audit |
| A6 | Real local OIDC, Kubernetes, restore, rollout/failure and security drills | OIDC/kind/restore pass; bad-image rollback and failed-migration drills remain |
| A7 | Production validator, release provenance, operator package and final acceptance report | Validator and release artifacts exist; final report requires all remaining evidence |

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
| P3 | Profiling, batching/scaling, resilience and deployment hardening | Capacity points retained; named failure/resharding acceptance still incomplete |
| P4 | Editorial intelligence design system and full dashboard transformation | Complete |
| P5 | Authentication/RBAC, retraining governance and release readiness | Complete as repository implementation; target IdP/cluster validation remains P6 |
| P6 | Real-data, performance, security, UI, deployment and public CI validation | Partial; research corrections, approved-site baseline and specific failure drills remain repository work |

## Detector-v2 research boundary

The follow-on packet-sequence/domain-invariance research has retained preliminary
evidence, but corrected partitioning and execution provenance are still required.
Its historical Markdown plan, reserved final environment, source hashes, aggregate JSON
reports, row-level embedding archives and retrospective integrity verifier are in
`docs/research-v2/MASTER_PLAN.md`,
`configs/research-v2/evidence-manifest.json`, and `scripts/verify_research_v2.py`.
The final v1/v2 scientific and operational boundary is recorded in
`docs/FINAL_ACCEPTANCE_REPORT.md`.
