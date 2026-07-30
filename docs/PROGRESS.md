# Progress

Last updated: 2026-07-30.

## Verified

- Empty workspace recovered onto `codex/aegisflow`.
- Upstream commit `277c4ff...` cloned and audited.
- Upstream tests fail at collection: missing `icecream`; an LFS checkpoint also
  failed pointer validation.
- Upstream license discrepancy documented (actual Apache-2.0, README says MIT).
- Complete typed vertical slice: demo/PCAP sensor, Redis streams, hybrid detector,
  PostgreSQL persistence, REST/WebSocket API, incidents, feedback, and React dashboard.
- Clean Compose replay persisted 6 flows, produced 5 alerts, and grouped 1 incident.
- PostgreSQL flush-order integration failure reproduced, fixed, and covered by a
  statement-order regression test.
- Python: 23 tests pass, Ruff passes, strict MyPy passes, measured coverage is 81%.
- Dashboard: ESLint, TypeScript/Vite build, Vitest, Playwright Chrome E2E, and
  `npm audit --audit-level=high` pass.
- Docker images build and run non-root; PostgreSQL/Redis stay internal to the Compose
  network; API/dashboard bind to loopback.
- Synthetic inference benchmark: 2,000 flows, 331.8 flows/s, 3.39 ms p95 and
  3.92 ms p99 on the recorded Windows host. Queue growth was not measured.

## Hard blockers and fallbacks

- None. Live packet capture and Suricata are not expected on Windows; fixture and
  PCAP adapters are the required fallback.

## Exact optional backlog

- Compact PyTorch denoising autoencoder. Acceptance: packaged in the same bundle,
  benign-only training, held-out anomaly calibration, CPU latency reported.
- Real NFStream Linux-container evaluation. Acceptance: fixture PCAP and explicit
  local interface succeed without temp-PCAP looping; otherwise Suricata flow JSON
  remains default.
- External explanation provider. Acceptance: disabled by default, sanitized schema,
  timeout/retry/rate cap/cache, deterministic fallback, no detector latency impact.
- Full Redis/PostgreSQL restart matrix. Acceptance: consumer-group recovery,
  idempotent replay, database retry, queue backlog assertions.
