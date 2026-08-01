# Progress

Last updated: 2026-08-01.

## Verified

- Empty workspace recovered onto `codex/aegisflow`.
- Upstream commit `277c4ff...` cloned and audited. Its tests fail at collection because
  `icecream` is missing, and one LFS checkpoint fails pointer validation.
- Upstream license discrepancy documented: the actual root license is Apache-2.0 while
  the upstream README says MIT.
- Complete typed vertical slice: demo/PCAP sensor, Redis streams, hybrid detector,
  PostgreSQL persistence, REST/WebSocket API, incidents, feedback, and React dashboard.
- Clean Compose replay persisted 6 flows, produced 5 alerts, and grouped 1 incident.
- PostgreSQL flush-order integration failure reproduced, fixed, and covered by a
  statement-order regression test.
- Python: 63 tests pass, Ruff passes across the repository, and strict MyPy passes
  across 46 source files. The last full measured
  coverage baseline before bundle v2 was 82%.
- Dashboard: ESLint, TypeScript/Vite build, Vitest, Playwright Chrome E2E, and
  `npm audit --audit-level=high` pass.
- Docker images build and run non-root; PostgreSQL/Redis stay internal to the Compose
  network; API/dashboard bind to loopback.
- Synthetic inference benchmark: 2,000 flows, 331.8 flows/s, 3.39 ms p95 and 3.92 ms
  p99 on the recorded Windows host. Queue growth was not measured in that run.
- Redis/PostgreSQL recovery matrix passes against Compose: abandoned detector work is
  claimed, a three-event backlog drains, Redis restarts without replacing consumers,
  PostgreSQL downtime leaves its event pending and records retry errors, and recovery
  persists it after restart. Replaying six deterministic IDs adds no duplicate rows.
- Queue lag and pending counts are exposed by Prometheus and the System Health API/UI.
- Smoke bundle v0.2.0 compares logistic regression, random forest, and MLP candidates;
  sigmoid-calibrates the selected classifier on grouped training folds; and packages a
  benign-only Isolation Forest plus benign-only CPU denoising autoencoder. The synthetic
  holdout measured 4/105 benign anomaly flags and 80/80 novel-behaviour fixture flags;
  these are installation evidence only, not production-quality claims.
- Bundle v2 verifies complete checksums plus manifest artifact hashes before loading,
  promotes `production.json` atomically with history, supports explicit rollback, and
  visibly falls back from a corrupt current version to the previous valid v0.1.0 bundle.
- Public GitHub repository created at `https://github.com/sting-raider/AegisFlow`; `main`
  contains the verified bundle-v2 milestone. The first remote run passed Python,
  dashboard, Compose and integration/E2E jobs; its security job failed before checkout
  because the Trivy action tag omitted the required `v` prefix. CI now pins the verified
  `aquasecurity/trivy-action@v0.36.0` release. Replacement run `30697502689` and the
  NFStream/Suricata milestone run `30698780511` completed successfully.
- NFStream 6.6.0 processes the bundled PCAP into two canonical flows inside a Linux
  container with networking disabled and all capabilities dropped. The dedicated live
  stage runs as UID 10001 and, with only `NET_RAW`, captured one repeated loopback-only
  UDP flow. The ordinary backend still executes with every capability dropped. Native
  NFStream does not load on Windows, where Scapy remains the documented PCAP fallback.
- Pinned Suricata 8.0.6 replayed the bundled three-packet fixture with no network and
  only `DAC_OVERRIDE`, loaded one safe rule, and emitted one alert, one DNS record, and two
  flow records. The incremental reader parsed all four with zero errors, hashed the DNS
  name, and correlated the alert to one of two flows. Ten focused tests plus Ruff and
  strict MyPy pass for the NFStream/Suricata slice.
- Dataset tooling now has an official-source catalog, checksum/size/provenance-enforced
  HTTPS downloader, named CIC-IDS2017/CSE-CIC-IDS2018/UNSW-NB15 and generic NFStream
  CSV adapters, sanitized quality/leakage reports, time/day/source/family splits, and
  compatible cross-dataset drift/evaluation. Fixture tests exercise every adapter and
  evaluation path; no public-dataset performance number is claimed without the data.
- Runtime drift now observes anomaly score, known confidence, normalized flow rate,
  duration, total bytes, packet length, and alert rate through bounded two-window
  monitors. New crossings are persisted idempotently before Redis acknowledgement and
  exposed by API/dashboard plus Prometheus count/magnitude metrics. Stored events
  explicitly prohibit automatic action and retraining eligibility.
- Incident explanations now run only on an analyst-requested API path. A recursive
  allow-list builds endpoint-free aggregate evidence for deterministic, remote
  OpenAI-compatible, or loopback-local rendering. Optional providers are disabled by
  default and bounded by HTTPS/loopback URL validation, explicit model configuration,
  timeout, retry cap, per-process rate limiting, response limits, and incident-version
  LRU caching. Every provider/configuration/rate failure returns a visibly deterministic
  fallback; dashboard text is labelled AI-generated or deterministic and cannot affect
  detection or authorize action. Provider protocol, retry, rate, cache, failure,
  privacy, API, repository, and UI behavior are covered in the green full suites.

## Hard blockers and fallbacks

- None. Windows cannot validate authorized live packet capture or native Suricata, so
  isolated Linux-container and fixture/PCAP evidence is required for those paths.

## Highest-priority required backlog

- Richer incidents/API/export/dashboard, remaining structured observability and
  input/backpressure hardening tracked in
  `docs/COMPLETION_AUDIT.md`.
