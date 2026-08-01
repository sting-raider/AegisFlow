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
- Python: 108 tests pass, Ruff passes across the repository, strict MyPy passes across
  53 source files, and the last measured backend coverage is 84%.
- Dashboard: ESLint, TypeScript/Vite build, Vitest, Playwright Chrome E2E, and
  `npm audit --audit-level=high` pass.
- Docker images build and run non-root; PostgreSQL/Redis stay internal to the Compose
  network; API/dashboard bind to loopback.
- Bounded-queue burst benchmark on the recorded Windows host generated 2,000 flows,
  processed 1,685 at 74.5 flows/s, explicitly dropped 315 after the 256-event queue
  saturated, and drained to zero. Inference measured 14.55/21.02/26.65 ms p50/p95/p99;
  queue-inclusive processing measured 4,124.57/4,357.90/4,382.78 ms. Average process CPU
  was 97.13% with a 319.4 MB RSS peak. This is a local synthetic overload measurement,
  not a production capacity claim.
- Redis/PostgreSQL recovery matrix passes against Compose: abandoned detector work is
  claimed, a three-event backlog drains, Redis restarts without replacing consumers,
  PostgreSQL downtime leaves its event pending and records retry errors, and recovery
  persists it after restart. Replaying six deterministic IDs adds no duplicate rows.
- Queue lag and pending counts are exposed by Prometheus and the System Health API/UI.
- Smoke bundle v0.3.0 compares logistic regression, random forest, and MLP candidates;
  sigmoid-calibrates the selected classifier on grouped training folds; and packages a
  benign-only Isolation Forest plus benign-only CPU denoising autoencoder. The synthetic
  final grouped test measured 2/105 benign anomaly flags and 80/80 novel-behaviour fixture flags;
  these are installation evidence only, not production-quality claims.
- Bundle v3 separates grouped train, calibration, and final test source groups. It stores
  a bounded 105-sample benign-only empirical CDF (69 distinct knots), so the runtime
  percentile is no longer an alias for the normalized anomaly score. A checked demo flow
  scored `0.355581` at empirical percentile `0.78123823`.
- Every fusion weight and threshold now loads from the checksummed bundle. The smoke-only
  selection loop compared 82 transparent configurations; it retained baseline weights
  and changed the anomaly threshold from `0.70` to `0.74`. On the untouched synthetic
  grouped test partition, final-verdict macro F1 was `0.73837` for the baseline and
  `0.74109` for the selected rule. These values validate machinery, not real traffic.
- Bundle v2 verifies complete checksums plus manifest artifact hashes before loading,
  promotes `production.json` atomically with history, supports explicit rollback, and
  visibly falls back from a corrupt current version to the previous valid v0.1.0 bundle.
- Public GitHub repository created at `https://github.com/sting-raider/AegisFlow`; `main`
  contains the verified bundle-v2 milestone. The first remote run passed Python,
  dashboard, Compose and integration/E2E jobs; its security job failed before checkout
  because the Trivy action tag omitted the required `v` prefix. CI now pins the verified
  `aquasecurity/trivy-action@v0.36.0` release. Replacement run `30697502689` and the
  NFStream/Suricata milestone run `30698780511` completed successfully.
- Optional-explanation milestone run `30700581424` passed Python, dashboard, security,
  Compose/live-container, and end-to-end integration jobs on public `main`.
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
- Incident correlation now requires ten-minute proximity plus at least one explainable
  affinity: same source, shared destination, common signature, common reason, a specific
  mapped attack stage, or repeated risk/severity escalation. Generic unknown/review
  stages and time alone cannot merge incidents. Detail responses derive source and
  destination sets, signatures, reasons, stages, escalation count, acknowledgement
  summary, alerts, and chronological timeline from durable source records. The dashboard
  exposes that evidence and status controls. Pure-rule tests cover every required rule,
  and repository/API/UI tests cover the integrated timeline.
- Retention is now configurable and scheduled after the first interval, with the same
  dependency-safe cleanup available as a one-shot command. Runs write bounded health
  events, remove feedback before alerts, and repair or remove affected incidents. Flow
  and alert CSV exports are row-bounded and column-allow-listed, pseudonymize addresses
  with an ephemeral per-export salt by default, require the configured API key for raw
  addresses, and escape spreadsheet formulas. Analyst-approved benign-new-behaviour
  feedback has a separate endpoint-free fixed-feature query/export. API list filtering,
  totals, alert acknowledgement, rich flow detail, UTC range validation, structured
  redacted global errors, retention/system status, and correlation IDs have focused
  integration coverage. Concrete PostgreSQL backup and restore-test commands are
  documented.
- Dashboard completeness now covers real overview throughput/severity/verdict/protocol/
  host/queue/model/drift analytics; live pause, filters, evidence provenance,
  acknowledgement and feedback; incident notes/timeline/status/explanation; paginated
  flow endpoint/protocol/time filters, selected anonymized export, detection/signature/
  feature detail; derived host risk/activity/protocol/alert history; model validation and
  score distributions; and retention/health ledgers. Incident notes persist as bounded
  audit events and remain excluded from detection, retraining and explanations. Browser
  QA exercised desktop and mobile layouts with no page overflow or console errors, and
  four component tests cover core analyst interactions. Missing backend telemetry stays
  visibly `not reported` rather than being fabricated.
- Ingress hardening now caps mutation bodies, WebSocket origins/connections/frames, Redis
  stream length, and serialized stream messages. Oversized WebSocket frames and malformed
  events become visible processing errors; dead letters retain only a hash and bounded
  structure, never the untrusted envelope. Queue capacity utilization and threshold
  transitions are explicit. Sensor, detector, API, access, and runtime logs are redacted
  one-line JSON with the required operational fields. Prometheus now exposes every
  brief-listed flow/signature/detection/alert/latency/queue/model/WebSocket/drift/database
  metric, while system status feeds real throughput, drops, latency, signature/Suricata,
  capacity, retention, and health values to the dashboard.
- Feature parity now includes 256 deterministic randomized valid-flow trials proving
  registry order and endpoint-identity independence, plus nonfinite/out-of-range tests.
  The repeatable bounded-queue performance test verifies event conservation, queue
  bounds, latency percentiles, CPU, and memory without an arbitrary CI threshold.
- Final hardening commit `fd25b15` is published on public `main`; GitHub Actions run
  `30703942894` passed Python/coverage/NFStream/training/migration, dashboard/audit,
  Compose/live-loopback, integration/Playwright, gitleaks, and Trivy jobs.
- Flow identity is now independent from semantic direction. Scapy uses SYN, unambiguous
  service-port, then first-packet evidence; NFStream preserves or safely corrects its
  `src2dst` direction; complete correlated Suricata `toserver`/`toclient` flow records
  take precedence. Destination port, packet/byte counters, and packet-direction samples
  follow the resulting initiator/responder orientation.
- AegisFlow now implements standard Community ID v1 and passes published Corelight TCP,
  UDP, and IPv6 reference vectors. An isolated pinned Suricata 8.0.6 replay emitted the
  same two IDs as the Scapy sensor for the bundled PCAP; direction reconciliation yielded
  two oriented flows, one correlated signature, and zero EVE processing errors.
- Exact public evaluation now shares `HybridPredictor` with runtime inference. The
  evaluator retrains the calibrated classifier, benign-only Isolation Forest and CPU
  denoising autoencoder, builds a benign empirical CDF, and applies the bundle-loaded
  fusion rule in batches. Focused parity coverage proves a runtime single-flow result
  matches batch scoring; the full local gate passes 111 Python tests, Ruff, strict MyPy
  across 56 source files, dashboard lint/build, and four dashboard tests.
- The reviewed official UNSW-NB15 training/testing partitions were downloaded through
  UNSW's public SharePoint path and retained only under ignored `data/`. SHA-256 and
  provenance sidecars identify 175,341 training and 82,332 testing rows. The sanitized
  exact-hybrid report is committed at
  `docs/evaluation/unsw-nb15-official-split.json`.
- The first public result is negative readiness evidence: fixed four-verdict macro F1 is
  0.156, weighted F1 is 0.294, benign false-positive rate is 64.4%, and 59,268 test rows
  enter `needs_review`. Batch scoring measured 2,070 flows/s on the published local Windows run,
  but 39.6% canonical train/test overlap and missing transport/flag/dispersion fields
  materially limit interpretation. Baseline and deployed thresholds tie on fixed-label
  macro F1; the apparent observed-label difference comes from which verdict labels are
  present, so it is not claimed as an improvement.

## Hard blockers and fallbacks

- Production-readiness is not yet proven. The exact official UNSW-NB15 result fails an
  acceptable false-positive standard, contains no unknown family, and cannot provide a
  time-based false-alert rate. Windows cannot validate authorized live capture, so
  isolated Linux-container evidence remains required for that path.

## Highest-priority required backlog

- Run reviewed public held-family and genuinely different cross-dataset experiments,
  add a time-bearing CIC source, and use the failure evidence to recalibrate/retrain
  without test leakage or automatic promotion.
- Add profiling, batching/worker scaling, enterprise
  auth/RBAC, production deployment assets, governed champion/challenger promotion, and
  the editorial dashboard transformation.
