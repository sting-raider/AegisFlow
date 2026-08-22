# Final acceptance report

Date: 2026-08-22.

This report closes the final model-research and production-acceptance phase. It is
assembled only from retained repository evidence: `docs/MODEL_RESEARCH_LOG.md`,
`docs/research/`, `docs/acceptance/`, `docs/benchmarks/`, `docs/error_analysis/`,
`docs/evaluation/`, and the frozen-evidence manifest
`configs/evaluation/frozen-evidence-v1.json`.

## 1. Exact repository commit

`7f543e6fd6c2e32272d96c54e0067b2bcaacd984` (public `main`, GitHub Actions run
`32569606185`: all ten jobs green, including Python, Compose, integration,
OIDC-integration, restore, release-evidence, security, security-acceptance,
dashboard, and kubernetes-integration).

## 2. Experiment protocol

The protocol is predeclared in `docs/MODEL_RESEARCH_LOG.md` and enforced by CI:

- Development evidence must come from newly acquired, checksum-reviewed public
  environments that are not registered as frozen-final sources; a preparation guard
  rejects any source hash listed in the frozen manifest.
- Frozen labels, metrics, predictions, errors, and distributions may never guide model,
  schema, hyperparameter, calibration, or threshold selection.
- A challenger must be selected on development evidence alone, then locked (code,
  configuration, thresholds, schema), before a single run against the frozen matrix is
  authorized. At most one final run per locked candidate.
- Every experiment records code commit, dataset fingerprints, splits/groups, seeds,
  preprocessing fit scope, estimator parameters, calibration scope, thresholds, and
  aggregate-only metrics with visible failures (`DEV-SUP-001`, `DEV-ANO-001`,
  `DEV-HYB-001`, `DEV-ERR-001`, `DEV-CAL-001`; research entries MR-000 through MR-008).

## 3. Development datasets

Three official non-frozen environments (`configs/datasets/development-pool-v1.json`,
quality reports in `docs/development/`):

| Source | Retained rows | Role |
|---|---|---|
| HIKARI-2021 v1.4.0 | 555,278 | Schema A aggregate benign+attacks |
| CSE-CIC-IDS2018 2018-02-28 capture | 606,902 | Schema A aggregate benign+attacks |
| IoT-23 (six capture groups) | 43,009 | Timestamped endpoints; full Schema B replay |

Raw files stay outside Git; only provenance, schemas, reports, and preparation tooling
are committed.

## 4. Frozen datasets

Four published reports are locked as final-rejection-only evidence in
`configs/evaluation/frozen-evidence-v1.json` with byte, configuration, source-data,
publication-commit, and publication-date fingerprints, verified by
`make frozen-evidence-check` in every CI run:

- `docs/evaluation/unsw-nb15-official-split.json`
- `docs/evaluation/unsw-nb15-held-exploits.json`
- `docs/evaluation/cse-cic-ids2018-thursday-time.json`
- `docs/evaluation/unsw-to-cse-cic-ids2018-thursday.json`

They reject the deployed smoke model (benign FPR approximately 64.4% official split;
2.1% direct unknown detection held-out exploits; 100% benign FPR UNSW→CSE;
essentially zero chronological later-infiltration recall). They were never used to
develop or select the challenger family.

## 5. Final feature schema

No challenger schema was promoted. The research outcome:

- Schema A (`2.0.0-research-a`, 24 portable features) is blocked for selection: a
  train-fit-only diagnostic predicts corpus origin at 0.95416 balanced accuracy.
- Removing all protocol/port/service categories yields a nine-feature numerical core at
  0.68428 origin accuracy (below the 0.90 block threshold); this core was used for the
  development experiments only.
- Schema B (`2.0.0-research-b`) adds 16 bounded temporal features computed by the shared
  runtime state machine over 10/60-second sensor+source windows, with parity tests,
  expiry, duplicate handling, and explicit unavailability when timestamps or endpoints
  are missing.
- Train-fit preprocessing clips at training-derived quantiles and robust-scales
  continuous features; ports are range/service categories, never magnitudes.

## 6. Selected model

**None.** No tested representation/model/calibration configuration met the predeclared
development objectives, so no candidate was eligible to be locked, and the frozen final
matrix was correctly never unsealed. The deployed bundle remains smoke-only v0.3.0,
rejected by all four frozen reports and prohibited from production promotion by the
governance gate.

## 7. Model comparison

Development evidence only (`docs/research/experiments/`):

- Supervised (`DEV-SUP-001`): logistic regression, sigmoid-calibrated random forest,
  HistGradientBoosting, compact MLP across three leave-one-environment-out rotations.
  Best mean macro F1 0.61474 (MLP) but worst-environment malicious recall 3.64% and
  worst benign FPR 18.20%; other models' worst recall reached zero.
- Benign-only anomaly (`DEV-ANO-001`): Isolation Forest, robust covariance, LOF novelty,
  one-class SVM, denoising autoencoder over six strict three-way rotations. Strongest
  mean direct unknown recall 6.28% (one-class SVM) with near-zero worst rotations;
  strongest mean detection-or-review 15.81% (robust covariance) with 10.85% worst FPR.

## 8. Held-family results

`DEV-HYB-001` and `DEV-CAL-001` held out whole IoT-23 attack families (command-and-
control, DDoS, port scan) from supervised fitting and tested them on separate captures:

- Full hybrid: mean direct detection 18.59%, worst 0.007%; mean suspicious-unknown
  direct recall 2.07%; mean detection-or-review 52.14%, worst 0.067%; worst benign FPR
  1.61%.
- Predeclared cross-fitted site-calibration ensemble (`DEV-CAL-001`): 0% direct
  command-and-control detection, 4.10% port-scan detection-or-review, 0% worst direct
  unknown recall, 1.09% worst benign FPR.

All fail the development objectives (unknown detection-or-review >= 80%, benign FPR
<= 1%, known recall >= 90%).

## 9. Cross-dataset results

- Development: every experiment above is leave-one-environment-out or three-way
  disjoint fit/calibration/test; adding sources did not produce stable transfer.
- Historical frozen cross-dataset evidence (UNSW→CSE) rejects the deployed smoke model
  with 100% benign FPR and saturated anomaly percentiles; it was not rerun for the
  challenger because no challenger qualified to cross that boundary.

## 10. Frozen acceptance results

Not executed for a challenger — by protocol. No candidate was locked, and running the
sealed matrix anyway would have spent final evidence on an ineligible model. The four
existing frozen reports continue to stand as rejection evidence for the deployed smoke
bundle only.

## 11. False-positive analysis

`DEV-ERR-001` (`docs/error_analysis/held-family-root-cause-v1.json`, aggregate-only)
identifies: device-calibration orientation swings (DDoS direct detection 0.00035 vs
0.99152 under HUE/Echo reversal), concentrated TCP/web high-packet benign error buckets,
and late-event misses; removing port context worsens worst-case FPR rather than fixing it.

## 12. Unknown-detection analysis

Direct suspicious-unknown recall is effectively zero in the worst rotation of every
tested family; detection-or-review never exceeds 15.81% mean (anomaly-only) or 52.14%
mean / 0.067% worst (hybrid). Root causes are flow-level observability limits
(zero/one-packet, zero-duration flows carrying too little behaviour) plus device-specific
benign baselines, not threshold placement. Classifier uncertainty and out-of-distribution
evidence remain separate signals in the runtime contract.

## 13. Ablation results

Nine ablations in `DEV-HYB-001` (supervised, anomaly, temporal context, pairwise fusions,
full hybrid, no-temporal, no-port-context): temporal context helps selected rotations but
is highly calibration-sensitive (context-only transfers with up to 38.90% benign FPR);
no-temporal is restrained (0.63% mean FPR) but worst detection-or-review falls to 9.02%.
No ablation meets objectives; signatures-only was marked not evaluable rather than
fabricated for the development pool.

## 14. Performance envelope

Local synthetic measurements, exact-conservation gated (`docs/benchmarks/`,
`docs/acceptance/sustained-compose-linux-ci-2026-08-13.json`):

- Detector burst batching: 153.50 → 3,496.81 flows/s on a 2,000-flow Windows burst
  (64-row hybrid batching).
- Durable Compose path, pre-fix incident-membership defect: 78.78 flows/s after bounded
  persistence transactions.
- Sustained 50 flows/s, 10 minutes: PASS — 30,000/30,000 durable, P95 2.002 s, max depth
  175, drain 1.35 s.
- Sustained 50 flows/s, 30 minutes (same host): capacity NO-GO — P95 73.03 s, max depth
  11,475, second-half growth +2.538 msg/s; API kill/restart recovered its backlog.
- Sustained 30 flows/s, 30 minutes, clean Linux runner (predeclared gates): **PASS** —
  exactly 54,000 published/persisted flows/detections/durable latency samples; publish
  rate 29.999999 flows/s; durable P95 3.336 s (< 5 s budget); maximum detection depth 75
  (< 10,000 bound); zero unexplained loss; zero final pending/lag; 3.9 s drain; all six
  sustainable criteria true (GitHub Actions run `31695359714`).
- Two-API-worker persistence partitioning/recovery drill: all 6,000 flows/detections
  durable, zero duplicates, every published event reconciled to a latency sample.

## 15. Capacity limitations

The sustained points are single-host, synthetic-paced workloads. Representative traffic,
multi-host orchestration, database/Redis server tracing, and deployment-specific capacity
validation remain open. The 30 flows/s point defines the validated local envelope;
higher rates were not sustainable on the recorded host at 30 minutes.

## 16. OIDC acceptance result

PASS. Optional local Dex profile (Dex v2.44.0) exercised discovery/JWKS, issuance,
server-derived viewer/analyst/admin roles, escalation denial, WebSocket authentication,
rate limits, audit attribution, key rotation (old denied, new accepted, 0.35 s), expiry,
and clock skew. Eleven checks passed in 95.08 s; no credentials recorded
(`docs/acceptance/oidc-ci-2026-08-13.json`). This validates the OIDC contract, not an
organizational IdP integration.

## 17. Kubernetes acceptance result

PASS. Disposable kind cluster (pinned node image, ingress-nginx v1.15.1 with verified
manifest checksum) deployed the actual Kustomize base: migrations ran
(`0003_incident_membership`), two replicas each of API/dashboard/detector became ready,
detector scaled to three and back, TLS ingress returned the expected responses,
NetworkPolicy denied an unlabelled Redis client, the model registry mounted, duplicate
replay stayed idempotent (6 flows / 6 detections / 5 alerts / 1 incident conserved),
API rolling replacement took 31.1 s, detector pod recovery 31.8 s, cleanup passed
(`docs/acceptance/kubernetes-ci-2026-08-22.json`, GitHub Actions run `32569606185`).
Failures found and fixed en route: PostgreSQL init needed a subdirectory PGDATA, the
non-root model seed required content-only copies, pod-identity turnover had to be awaited
after rollout status, and ingress admission readiness required a webhook-aware apply
retry (completed certgen jobs are TTL-deleted almost immediately). This validates
disposable single-node deployment mechanics, not managed-cloud readiness.

## 18. Restore-drill result

PASS. Fail-closed drill created an isolated Compose project, seeded deterministic state,
recorded counts and primary-identity digests for all 15 tables, produced a custom-format
backup, destroyed only the disposable database, restored to a clean instance, re-ran
migrations (`0003_incident_membership`), matched every count and identity digest, and
smoked the real API (6 flows, 5 alerts, 1 incident) in 102 s
(`docs/acceptance/restore-ci-2026-08-13.json`, run `31689272384`). Managed backup,
off-host durability, encryption, RPO/RTO remain external.

## 19. Failure/rollback results

Redis/PostgreSQL recovery matrix passes (abandoned work reclaimed, backlog drains,
restarts preserve pending events, replay adds no duplicates); queue lag/pending exposed
via Prometheus/API/dashboard; corrupt-model fallback to previous valid bundle verified;
model promotion requires independent approval with atomic pointer changes, audited
rollback, and crash reconciliation; API replacement recovers dashboard proxying without
dashboard restart; API kill during sustained load reclaims its backlog and drains.
Recovery objectives measured where stated above; zero silent data loss observed within
the tested scenarios.

## 20. Security acceptance

PASS. Seventy-four controlled adversarial tests across six categories (identity/browser,
export/privacy, model/artifact, untrusted queue input, optional provider, production
configuration/privilege), including malformed/oversized JWTs, algorithm confusion,
oversized JWKS, path variants, and unsafe-config rejection via `make production-check`
(`docs/acceptance/security-ci-2026-08-13.json`, run `31692826577`). Multi-tenancy is an
explicit architectural decision: single organization, single security domain per
deployment; RBAC is not tenant isolation. An organizational penetration test remains
external.

## 21. Remaining external dependencies

Organizational IdP validation; managed PostgreSQL/Redis; real target-cluster deployment
with representative capacity; registry digests/signing for releases; organizational
penetration test; representative sustained traffic; off-host managed backup/RPO-RTO
validation; and — decisive — a detector model that passes governed acceptance gates.

## 22. GO / NO-GO verdict

**Detector: NO-GO.** The challenger program receives a documented development scientific
NO-GO (`docs/research/conclusion.md`): no representation/model/calibration configuration
met the predeclared development objectives, so no candidate could be locked and the
frozen final matrix remains sealed. Root cause is attributed to flow-level observability
limits and environment-specific benign baselines under the current portable feature
contract — not to a single threshold, architecture, or implementation defect. The
deployed smoke bundle stays rejected and blocked from promotion by governance.

**Platform: complete engineering/evaluation platform with validated local deployment
mechanics.** All production-acceptance exercises defined for the local envelope pass:
sustained conservation-gated throughput, OIDC contract, Kubernetes deployment mechanics,
restore drill, failure/rollback drills, security acceptance, release evidence with SBOM
and manifest, production-check fail-closed gate, and operator documentation. Under the
plan's stop conditions this is Outcome B: the engineering platform is complete while the
detector receives an explicit NO-GO. AegisFlow must not be called a production detector.

## 23. Exact claims that may safely be made about AegisFlow

1. It is a tested real-time NIDS engineering and evaluation platform with PCAP/demo/
   authorized-live capture, NFStream/Scapy/Suricata interoperability, Community ID v1,
   semantic flow direction, Redis streaming, PostgreSQL persistence, hybrid detection,
   incidents, feedback, drift monitoring, governed model registry, RBAC/OIDC/service
   identities, and a seven-view analyst dashboard.
2. Its current bundled model is rejected by four frozen public-data evaluations and is
   installation evidence only.
3. Its challenger family failed predeclared development objectives across supervised,
   anomaly, hybrid, temporal, and site-calibrated configurations; the strongest next
   research direction is richer observable semantics (packet-sequence summaries,
   connection-state transitions, privacy-reviewed DNS/TLS metadata) plus independently
   reviewed environments with full temporal prerequisites, before any new candidate.
4. Within its tested local envelope (single host, synthetic paced load up to 30 durable
   flows/s over 30 minutes on a clean Linux runner), it conserves every event, bounds
   queues, returns to steady state, survives component restarts, restores databases
   exactly, and fails closed on unsafe configuration.
5. Deployment mechanics (Compose, Kustomize-on-kind, OIDC contract, backup/restore,
   rollback drills, security controls) are validated locally; managed-cloud,
   multi-host, organizational-identity, and representative-capacity claims require
   target-environment evidence.
6. Detection never triggers automatic blocking; payloads are never stored; suspicious
   traffic never enters a benign baseline automatically; AI explanations cannot affect
   detection.
