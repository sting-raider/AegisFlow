# Progress

Last updated: 2026-08-11.

## Active final model and production-acceptance phase

The engineering/evaluation platform is demoable, but the project is **not complete under
the final acceptance brief**. The currently deployed smoke model is rejected by all four
frozen public-data evaluations and must not be described as a production detector. Work
now follows the model-research and production-acceptance phases in `docs/MASTER_PLAN.md`.

- The four legacy public-data reports are frozen as final rejection evidence in
  `configs/evaluation/frozen-evidence-v1.json`. The manifest records exact report,
  evaluation-configuration, source-dataset, publication-commit, and publication-time
  fingerprints. `make frozen-evidence-check` verifies the boundary and CI runs it.
- Frozen labels, metrics, predictions, errors, and distributions are prohibited from
  development or threshold selection. A challenger must be locked using fresh development
  evidence before a single final acceptance run is authorized.
- The initial portability audit found that the current 18-feature schema uses raw
  heavy-tailed values, a numeric destination port, no missingness indicators, no protocol
  encoding, and zero substitution for unavailable UNSW fields. These are plausible
  dataset-origin shortcuts and make the current schema unsuitable as the final challenger
  representation without further evidence.
- The fresh development pool now contains three official, non-frozen,
  checksum-reviewed environments: HIKARI-2021 v1.4.0 (555,278 retained rows), the
  distinct CSE-CIC-IDS2018 2018-02-28 capture (606,902 retained rows), and 43,009
  IoT-23 rows across six capture groups. All pass blocking quality checks, and a
  development guard rejects source hashes registered as frozen-final evidence. Raw files
  remain ignored.
- IoT-23 supplies timestamps, endpoints, protocols, ports, and directional counts. All
  43,009 rows replay through the shared Schema B state machine. Unset Zeek duration and
  zero-packet semantics are explicit, and no endpoint identity enters committed features
  or reports.
- The three-environment, deduplicated dataset-origin diagnostic still blocks full Schema
  A at 0.95416 balanced accuracy. Removing protocol/port/service categories lowers it to
  0.68428, so only the reduced numerical core clears the 0.90 shortcut threshold.
- A clean-commit development harness now compares logistic regression, sigmoid-calibrated
  random forest, HistGradientBoosting, and the compact MLP across all three leave-one-
  environment-out rotations. It applies train-only preprocessing, deterministic binary-
  class caps, exact-vector deduplication, conflicting-label removal, fixed untuned 0.5
  thresholds, and aggregate-only resource/calibration/error reporting. `DEV-SUP-001`
  completed all three rotations. No model qualifies: the compact MLP is strongest on mean
  macro F1 (0.61474), but worst-environment malicious recall is 3.64% and worst benign FPR
  is 18.20%. No result was used to select or lock a candidate. A CI verifier binds the
  clean code commit, source fingerprints, schema/order, seed, aggregate report hashes,
  and development-only/frozen-source policy and rejects report tampering or per-row
  predictions.
- A three-way benign-only anomaly experiment compares Isolation Forest, robust
  covariance, Local Outlier Factor novelty, one-class SVM, and a CPU denoising
  autoencoder. Fit, threshold-calibration, and test environments are mutually disjoint;
  both fit/calibration orientations are repeated for every held environment. Direct and
  review thresholds come only from calibration benign FPR budgets, every test attack
  family is absent from fit/calibration, and model failures remain visible. `DEV-ANO-001`
  completed all 30 runs. No family qualifies: best mean direct unknown recall is 6.28%,
  every family has a zero or near-zero worst-rotation result, and the strongest mean
  detection-or-review result is 15.81% with 10.85% worst benign FPR. No candidate was
  selected or locked.
- `DEV-HYB-001` removes each held family from HIKARI/CSE supervised fitting, uses the two
  all-benign IoT device captures for anomaly fit/calibration in both orientations, and
  tests three eligible families on separate attack captures. Nine ablations cover
  supervised, anomaly, temporal context, pairwise fusion, full hybrid, no-temporal, and
  no-port-context views. The full hybrid fails: worst direct and suspicious-unknown recall
  are effectively zero, worst detection-or-review is 0.067%, and worst benign FPR is
  1.61%. Temporal context helps selected rotations but is highly calibration-sensitive;
  no candidate was selected or locked.
- `DEV-ERR-001` groups the fixed hybrid errors without retaining row-level output. It
  identifies device-calibration orientation, zero/one-packet and zero-duration attack
  observability, late-event misses, and concentrated TCP/web high-packet benign errors as
  the dominant limitations. Port-context removal is not a remedy.
- `DEV-CAL-001` is the predeclared cross-fitted environment-aware calibration ensemble.
  It removes the arbitrary HUE/Echo orientation but still has 0% direct C2 detection,
  4.10% port-scan detection-or-review, 0% worst direct unknown recall, and 1.09% worst
  benign FPR. The current challenger family receives a development scientific NO-GO. No
  candidate is locked and the frozen final matrix remains sealed.
- Remaining repository work proceeds to sustained
  performance, real local OIDC/Kubernetes, restore, rollback/failure, security, and final
  GO/NO-GO evidence.
- Research Schema A now emits 24 portable features from exporter-independent counts,
  fractions, derived rates, log transforms, protocol categories, port ranges, service
  families, and explicit port missingness; it never exposes raw endpoint identity or a
  continuous port magnitude. Research Schema B adds 16 AegisFlow-owned temporal signals
  over bounded 10/60-second sensor+source windows. The shared implementation handles
  cold starts, expiry, duplicates, bounded source/event state, sensor isolation, IPv4/IPv6,
  and late events. Dataset adapters call the same vectorizer/state machine and decline
  Schema B when any row lacks a valid timestamp or endpoint.
- Train-fit preprocessing clips only at training-derived quantiles, robust-scales
  continuous features, and preserves declared categorical/binary geometry. No candidate
  has been trained or selected yet; origin-classifier and fresh-data evidence remain open.

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
- Python: 169 tests pass, Ruff passes across the repository, strict MyPy passes across
  78 source files including migrations, and measured backend coverage is 84%.
- Dashboard: ESLint, TypeScript/Vite build, Vitest, Playwright Chrome E2E, and
  `npm audit --audit-level=high` pass.
- Docker images build and run non-root; PostgreSQL/Redis stay internal to the Compose
  network; API/dashboard bind to loopback.
- Exact runtime profiling isolated single-row Isolation Forest traversal as 66.3% of
  measured detector stage time. On the same 2,000-flow Windows burst with no drops,
  64-row hybrid batching raised throughput from 153.50 to 3,496.81 flows/s (22.78x).
  The local Compose Redis-to-PostgreSQL gate initially timed out at 150 seconds with
  1,828/2,000 rows durable; bounded persistence transactions and transaction-local
  incident-context caching then completed 2,000/2,000 in 25.39 seconds (78.78 flows/s)
  with zero final pending or lag. A two-detector smoke exercised eight batches on each
  replica and drained both queues. These are synthetic single-host measurements, not
  production capacity claims; exact artifacts live under `docs/benchmarks/`.
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
- The seven dashboard views now share a light-first editorial intelligence system with
  functional navigation labels, an asymmetric overview lead, serif/sans/mono type roles,
  mineral paper and restrained evidence accents, a single live-signal ribbon, automatic
  dark mode, and responsive desktop/mobile layouts. Chromium acceptance now has two
  scenarios: the complete analyst path plus zero Axe violations across all seven views
  and the evidence dialog. It also verifies the skip link, current-page state, modal
  labelling/autofocus, and reliable Escape dismissal. Current 1440x900 and 390x844
  screenshots were regenerated from the running Compose demo.
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
  matches batch scoring; the current full local gate passes 160 Python tests, Ruff,
  strict MyPy across 70 source files, dashboard lint/build, and four dashboard tests.
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
- Public split coverage now includes all requested evaluation modes that the reviewed
  sources support. Leaving all 44,525 `exploits` rows out of UNSW fitting/calibration
  yields 2.1% direct suspicious-unknown detection and 38.6% detection-or-review. A true
  UNSW-to-CSE-CIC-IDS2018 run scores 328,181 valid independent flows with zero canonical
  overlap, but produces 100% benign FPR, 18.9% direct unknown detection, about 19,649
  false alerts/hour, and saturated anomaly percentiles. A CSE chronological test has
  1.15% benign FPR but essentially zero later infiltration recall. These reports reject
  the current model; none is a production claim.
- Official CSE ingestion now audits 25 repeated shard headers and 2,919 non-finite or
  registry-invalid CICFlowMeter rate rows instead of turning them into a class or benign
  result. The source misspelling `Infilteration` maps to `infiltration`. Exact leakage
  profiling no longer stringifies high-cardinality columns, and a one-source time split
  uses chronological internal calibration before its untouched final test.
- Evaluation report schema 1.1 records row exclusions and an explicit review gate for
  macro F1, benign FPR, unknown detection/review, calibration, replay-hour false alerts,
  and overlap. Every published report fails. The gate can reject but never promote a
  model automatically.
- Non-demo access now has explicit OIDC and hashed service-key modes. Asymmetric token
  verification, issuer/audience/time checks, server-derived viewer/analyst/admin roles,
  authenticated WebSockets, bounded per-principal limits, safe errors, and durable
  attribution cover all versioned API and metrics routes. Unknown key IDs cannot amplify
  JWKS refreshes, and CORS rejects wildcards and non-loopback cleartext origins. Demo
  identity is available only while demo mode is enabled. A real organizational IdP,
  shared gateway limiter, session UX, and multi-tenancy remain target-deployment work.
- Challenger governance now binds a checksum-valid v3 bundle to immutable schema-1.1
  exact-hybrid reports covering grouped/source-file, chronological, held-family, and
  cross-dataset modes. Passing reports additionally bind the checksum-file digest and
  valid train/test fingerprints. Failed evidence creates a durable rejection; passing evidence only
  permits independent review. Creator self-review is prohibited, promotion requires a
  different approver, every byte is revalidated, pointer changes are atomic, restart is
  explicit, crash-pending state is reconciled, and rollback is audited. The four published
  reports remain rejection evidence and cannot be overridden.
- A production Compose override forces non-demo OIDC, mounted database secrets, health,
  resource and log bounds, and read-only detector model access. A Kustomize baseline adds
  non-root/read-only workloads, probes, disruption budgets, TLS ingress, and default-deny
  ingress policy while assuming managed PostgreSQL/Redis and out-of-band secrets.
  PostgreSQL advisory locking serializes concurrent migration init, and a single
  `Forbid`-concurrency CronJob owns retention for replicated APIs. All five
  Compose configurations render and `kubectl kustomize` passes locally. These are deployment
  templates, not evidence of a real IdP, managed service, restore drill, or cluster rollout.
- The 2026-08-10 validation rebuilt the real demo images, upgraded PostgreSQL through
  Alembic 0002, verified the governance/audit tables and demo identity, replayed the six
  safe deterministic flows, and passed Chromium E2E. Frontend lint/build, four Vitest
  interactions, `npm audit` with zero vulnerabilities, 160 Python tests, and 84% coverage
  also pass. An API-only container replacement initially exposed a stale Nginx upstream;
  Docker DNS re-resolution now restores dashboard-proxied readiness without restarting
  the dashboard, and Chromium passes after that forced replacement.
- Enterprise milestone commit `70e188e` is published on public `main`. GitHub Actions run
  `31340692583` passed all Python/coverage/migration/NFStream/training, dashboard/audit,
  Compose/Kustomize/live-loopback, forced API-replacement/Playwright, Gitleaks, and Trivy
  jobs.

## Hard blockers and fallbacks

- Production-readiness is not yet proven. Official split, held-family, chronological,
  and true cross-dataset evidence all reject the current model for different reasons;
  tuning against those final reports would be test leakage. Windows cannot validate
  authorized live capture, so isolated Linux-container evidence remains required for
  that path.
- Runtime mechanics are materially stronger, but representative sustained traffic,
  Redis/PostgreSQL server tracing, multi-host orchestration, and deployment-specific
  capacity validation remain open. The 78.78 flows/s Compose result is database-bound
  and must not be generalized beyond the recorded host and synthetic workload.
- The repository implements the identity, governance, and deployment control planes, but
  has not been connected to a real organizational IdP or deployed to an external cluster.

## Highest-priority required backlog

- Build a feature-compatible multi-source challenger with fresh fit/calibration evidence
  and governed review; keep all published public reports frozen as final tests.
- Extend runtime evidence with sustained representative replay and multi-host scaling;
  exercise the templates with a real IdP, managed data services, restore drill, and
  representative target-cluster capacity tests.
