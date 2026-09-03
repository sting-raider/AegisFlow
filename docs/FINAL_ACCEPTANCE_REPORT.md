# Final acceptance report

Date: 2026-09-03 (corrected research; operational evidence through 2026-08-23).

Status: **incomplete**. The 2026-09-02 audit supersedes the earlier closure verdict.
See `docs/REQUIREMENTS_AUDIT.md` for research-validity and acceptance gaps. This draft
assembles historical repository evidence: `docs/MODEL_RESEARCH_LOG.md`,
`docs/research/`, `docs/acceptance/`, `docs/benchmarks/`, `docs/error_analysis/`,
`docs/evaluation/`, `docs/research-v2/`, and the frozen-evidence manifest
`configs/evaluation/frozen-evidence-v1.json`.

## 1. Exact repository commit

`88ea3801886fd3b27563aab5f52a52d1272e2d80` (public `main`, GitHub Actions run
`32635976457`: all ten jobs green, including Python, Compose, integration,
OIDC-integration, restore, release-evidence, security, security-acceptance,
dashboard, and kubernetes-integration). That run predates the new v2 archive verifier.
Detector-v2 artifacts were published by commit
`85a20367250475abe70da1da28b6ff672b7e8e59`; their actual execution commits are not
established by the reports. Four local smoke-model registry files are intentionally
uncommitted and are excluded from this acceptance commit.

Subsequent corrected research is separately bound to its actual clean execution commits.
Latest: `DEV2-MISSINGNESS-001` executed from `b83f184d583d5d1f719c1be4702968516c3fd5f9`
(runner CI `33715446245` passed), producing 84 evaluated models, 24 transformed-alias
entries and 168 evaluated sites in 633.044 seconds. The paired negative/mixed results
are in `docs/research-v2/registered-results/DEV2-MISSINGNESS-001.*`. This updates the
development record, not the final acceptance verdict. The full brief remains incomplete.

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
- The v1 experiment harness records code commit, dataset fingerprints, splits/groups, seeds,
  preprocessing fit scope, estimator parameters, calibration scope, thresholds, and
  aggregate-only metrics with visible failures (`DEV-SUP-001`, `DEV-ANO-001`,
  `DEV-HYB-001`, `DEV-ERR-001`, `DEV-CAL-001`; research entries MR-000 through MR-008).

Detector-v2 has a historical Markdown plan and a retrospective archive policy recorded
on 2026-09-02 in `configs/research-v2/protocol.json`. The latter is not a pre-experiment
registration. `make research-v2-check` binds six prepared source records, five aggregate
JSON reports and six row-level embedding archives, using LF-normalized UTF-8 hashes
for JSON and byte hashes for NPZ. It checks archive boundaries, not scientific validity.
The newly configured CI step still requires a green milestone run. Corrected experiments
must record actual execution commit, data/splits/configuration and measured costs.

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

Detector-v2 independently declared eight official Stratosphere IoT-23 scenarios and
prepared six checksum-pinned captures (6,671 deduplicated labeled flows) for development:
34-1 Mirai, 8-1 Hakai, 42-1 and 20-1 benign-leaning captures, and honeypots 4-1 and 5-1.
The two additional declared real-device captures remain unprepared, and the separate
CTU-13 scenario-8 (rbot) environment is reserved for a single locked-candidate run but
was never acquired, queried, or used for selection. See
`docs/research-v2/DATASETS.md` and `configs/research-v2/pool-hashes.json`.

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

The v2 pool is development-only and has no source-hash intersection with this frozen
manifest. Its reservation and sealed status are checked by
`configs/research-v2/evidence-manifest.json`.

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
- The v2 packet-sequence contract carries signed log1p packet sizes, log1p inter-arrival
  times, semantic direction, normalized position, and an explicit padding mask for the
  first 20 observed packets, plus bounded TCP connection-state features. Payload contents
  and endpoint identity are never model features.
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

Detector-v2 evidence (`docs/research-v2/experiments/`) adds masked sequence MLP/CNN and
aggregate+connection-state fusion models. Site-relative calibration and a weak domain
adversary are evaluated as separate, transparent ablations; no v2 configuration is a
production selection.

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

The historical v2 HF1/HF2 results are cross-capture C&C tests, not strict held-family
evidence: C&C was allowed in fit. HF3 excludes C&C but reuses site-calibration data in
fitting and includes non-held families in evaluation. None supports a strict-family
acceptance claim. Corrected runners enforce row/observation isolation, label-family
exclusion and independent benign testing. FAMILY-002 completed all six corrected
rotations; it fails development objectives, with zero C&C/DDoS detection-or-review and
worst independent benign FPR 47.51%. MISSINGNESS-001 adds registered cross-capture
comparisons, explicitly identifying which test families were present in fitting.
Neither is the final frozen acceptance matrix.

## 9. Cross-dataset results

- v1 development experiments use leave-environment-out or disjoint calibration designs;
  the audit found fit/calibration overlap in v2 FAMILY/DANN, so the same statement
  cannot be extended to all v2 experiments.
- Detector-v2 global thresholds produce 0% recall in the hard fit-Hakai/test-Mirai
  direction despite PR-AUC 0.85--0.98; approved target-site p990 calibration recovers
  90.6--90.9% recall at nominal 1% site FPR. The mirrored direction is materially easier,
  demonstrating asymmetric environment transfer rather than a universal result.
- Raw-feature v2 origin BA reaches 0.797, but DANN learned embeddings reach
  0.93874--0.94378, exceeding the 0.90 threshold. The raw-feature result cannot establish
  domain-invariant learned embeddings. Neither is a frozen-final score.
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
The v2 aggregate-only error analysis adds score inversion across sites, tiny benign
calibration pools, repetitive-family deduplication, and honeypot benign noise as the
dominant causes of the asymmetric HF1/HF3 result.

## 12. Unknown-detection analysis

Direct suspicious-unknown recall is effectively zero in the worst rotation of every
tested family; detection-or-review never exceeds 15.81% mean (anomaly-only) or 52.14%
mean / 0.067% worst (hybrid). Root causes are flow-level observability limits
(zero/one-packet, zero-duration flows carrying too little behaviour) plus device-specific
benign baselines, not threshold placement. Classifier uncertainty and out-of-distribution
evidence remain separate signals in the runtime contract. In v2, Mahalanobis OOD catches
structurally distinct DDoS/port-scan rows at 100% in HF2, but not C&C variants; the known
and OOD channels remain explicitly separate.

## 13. Ablation results

Nine ablations in `DEV-HYB-001` (supervised, anomaly, temporal context, pairwise fusions,
full hybrid, no-temporal, no-port-context): temporal context helps selected rotations but
is highly calibration-sensitive (context-only transfers with up to 38.90% benign FPR);
no-temporal is restrained (0.63% mean FPR) but worst detection-or-review falls to 9.02%.
No ablation meets objectives; signatures-only was marked not evaluable rather than
fabricated for the development pool. V2 compares aggregate-only, sequence-only, fused,
site-calibrated, and domain-adversarial modes; lambda=0.1 reduces incidental benign flags
from 28.26% to 0% while preserving hard-direction recall (91.07% to 90.58%), but cannot
remove the HF1/HF3 collapse or unmet calibration gates.

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
- Detector-v2 latency/throughput: not verified. The earlier prose figures lack a retained
  machine-readable benchmark and cannot establish a performance gate.

## 15. Capacity limitations

The sustained points are single-host, synthetic-paced workloads. Representative traffic,
multi-host orchestration, database/Redis server tracing, and deployment-specific capacity
validation remain external follow-up. The 30 flows/s point defines the validated local
envelope; higher rates were not sustainable on the recorded host at 30 minutes. V2 CPU
cost must be measured reproducibly before any performance or candidate claim.

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

Partial. Bad API-image rollback, bad detector-image rollback, and failed migration
simulation still need dedicated measured drills. Pod replacement is not image rollback.

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
Organizational services require external coordination. Corrected model research,
site-baseline activation, and the missing acceptance drills remain repository work;
they are not external dependencies or waived requirements.

## 22. GO / NO-GO verdict

**Detector: NO-GO; full final-phase scope: incomplete.** V1 development rejection stands.
V2 has known methodological defects and insufficient provenance; corrected experiments
are required. No challenger is eligible for promotion or a frozen-final run. These facts
do not establish the full brief's Outcome B stop condition.

The engineering baseline is demoable, with retained local OIDC, restore, kind and capacity
evidence. Deployed approved-site baseline activation, named rollback/failure drills,
partitioning acceptance and research corrections remain open in `REQUIREMENTS_AUDIT.md`.

## 23. Exact claims that may safely be made about AegisFlow

1. It is a tested real-time NIDS engineering and evaluation platform with PCAP/demo/
   authorized-live capture, NFStream/Scapy/Suricata interoperability, Community ID v1,
   semantic flow direction, Redis streaming, PostgreSQL persistence, hybrid detection,
   incidents, feedback, drift monitoring, governed model registry, RBAC/OIDC/service
   identities, and a seven-view analyst dashboard.
2. Its current bundled model is rejected by four frozen public-data evaluations and is
   installation evidence only.
3. Its v1 challenger family failed predeclared development objectives across supervised,
   anomaly, hybrid, temporal, and site-calibrated configurations. Detector-v2 implements
   sequence and connection-state research representations; its historical performance
   claims need corrected partitioning and provenance before scientific comparison.
4. Within its tested local envelope (single host, synthetic paced load up to 30 durable
   flows/s over 30 minutes on a clean Linux runner), it conserves every event, bounds
   queues, returns to steady state, survives component restarts, restores databases
   exactly, and fails closed on unsafe configuration.
5. Recorded deployment mechanics (Compose, Kustomize-on-kind, OIDC contract, backup/restore,
   selected recovery tests, security controls) were exercised locally; remaining rollback
   drills are open. Managed-cloud,
   multi-host, organizational-identity, and representative-capacity claims require
   target-environment evidence.
6. Detection never triggers automatic blocking; payloads are never stored; suspicious
   traffic never enters a benign baseline automatically; AI explanations cannot affect
   detection.
7. Detector-v2's five aggregate JSON reports and six row-level embedding archives have
   a retrospective integrity guard. Integrity is not scientific validation. No v2 model
   is deployed or eligible for production promotion.
