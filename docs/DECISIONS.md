# Decision log

## D-001 — Clean-room rewrite

Use upstream as an architectural reference only. Its feature/inference parity and
packaging are unsafe to preserve, and the actual Apache-2.0 license conflicts with
the brief's MIT description. Alternative: fork and refactor. Rejected because it
would retain two UI generations, incomplete dependencies, and ambiguous contracts.

## D-002 — Distributed production profile, self-contained demo fallback

Use Redis Streams and PostgreSQL in Compose. The offline demo may use a bounded
in-process queue and SQLite while exercising the same domain logic. This keeps CI
and faculty demos reliable when Docker is missing, while integration tests validate
the infrastructure profile separately.

## D-003 — Scapy adapter before NFStream

Use a small deterministic Scapy flow aggregator for bundled PCAPs. NFStream remains
an optional adapter to evaluate in Linux containers. This avoids native-install
fragility and makes schema semantics testable. The live mode remains Linux-only and
explicit.

## D-004 — Conservative open-set baseline

Use calibrated supervised probabilities plus an Isolation Forest and compact denoising
autoencoder trained only on benign smoke data. No anomaly is called a zero-day. Both
anomaly signals are normalized against a held-out benign tail budget before fusion.

## D-005 — Dashboard visual language

Audience: a SOC analyst or faculty reviewer. Job: understand why traffic was flagged
within one glance. Palette: `deep channel #0B1821`, `slate water #17313D`,
`chart fog #D9E3E8`, `signal coral #FF735C`, `sonar teal #53C7C2`, and
`warning amber #E9B44C`. Display/section type uses Bahnschrift Condensed, body uses
Segoe UI, and data uses Cascadia Mono. The signature element is a live “flowline”
strip that maps detections to packet-like marks. A generic neon-black cyber theme
was rejected; the revised navigation-chart language is specific to network flow,
keeps data legible, and spends visual boldness on one operational element.

## D-006 — Self-contained demo image

Bake the small checksum-verified smoke bundle into the backend demo image after
training. This avoids host bind-mount failures on Docker Desktop, makes offline
replay reproducible, and keeps the runtime filesystem read-only. A model promotion
therefore requires rebuilding the backend image. External production registries
remain valid only when they are immutable, access-controlled, and mounted read-only.

PostgreSQL and Redis are reachable only on the Compose network. Only the API and
dashboard bind loopback host ports, which avoids collisions and removes unnecessary
host exposure.

## D-007 — At-least-once recovery with acknowledgement after durability

Redis stream entries are acknowledged only after the downstream result is published or
the database transaction commits. A schema-invalid event is published to the dead-letter
stream before acknowledgement. Transient Redis failures use bounded exponential backoff;
transient database failures use bounded retries and leave the entry pending after the
retry budget is exhausted. Consumers claim entries that exceed a configurable idle time
(`AEGISFLOW_PENDING_IDLE_MS`, 30 seconds by default), and database UUID constraints make
replay idempotent. This favors visible at-least-once delivery over silent event loss.

Compose uses `unless-stopped` for the long-running stateful and application services.
Queue lag and pending counts are observable through the API, dashboard, and Prometheus.
Automatic blocking remains prohibited regardless of recovery or detection outcome.

## D-008 — Versioned dual-signal bundles with safe fallback

Bundle schema v2 adds a CPU-only PyTorch denoising autoencoder state dictionary while
retaining the trusted-local joblib artifacts. The manifest duplicates hashes for the four
executable model artifacts in addition to the complete checksum file. A candidate is
fully validated before `production.json` is atomically replaced; promotion records a
bounded version history, explicit rollback uses the same validation path, and startup
falls back to a previous valid version with a surfaced warning. Bundle v1 remains
loadable solely as a recovery target. A mandatory v2-only migration was rejected because
it would remove the known-good fallback during rollout.

## D-009 — NFStream live target with portable PCAP fallback

Use NFStream 6.6.0 for completed-flow PCAP and explicit Linux live capture, while
retaining the deterministic Scapy adapter as the portable fallback. Live capture uses
a separate Docker build target so `cap_net_raw` is present only on that target's Python
interpreter; granting it to the shared backend interpreter made ordinary
`cap_drop: ALL` containers fail at exec. The live container remains non-root,
non-promiscuous, read-only, and receives only `NET_RAW`. NFStream's Windows native
engine does not load reliably, so forcing it as the only adapter was rejected.

## D-010 — Independent, pinned Suricata evidence

Run Suricata as optional infrastructure rather than an application dependency. Pin
8.0.6, use an isolated no-network profile with only `DAC_OVERRIDE` for PCAP rule
evaluation (the image config is mode `0600` and fresh output binds are root-owned), and
keep Linux live capture behind an explicit interface plus narrowly declared
capabilities. EVE ingestion retains only allow-listed or hashed metadata, surfaces
malformed records, and correlates without making Suricata mandatory for demo mode.
Automatic rule downloads and unrestricted raw EVE persistence were rejected.

## D-011 — Canonical public-data adapters with explicit approximation

Map CIC-IDS2017 and CSE-CIC-IDS2018 CICFlowMeter columns, UNSW-NB15 flow columns, and
generic NFStream CSV into the same 18-feature registry used at runtime. CIC time units
are converted explicitly. UNSW fields with no defensible equivalent are zero-filled
and recorded as adapter notes instead of inventing values. Identifiers are analyzed for
leakage but never enter the feature array or persisted report. Automated source
downloads require HTTPS plus a user-reviewed checksum; silently choosing a convenient
mirror or publishing fabricated public-dataset metrics was rejected.

## D-012 — Durable distribution monitoring without adaptive mutation

Use bounded two-window mean-shift monitors for anomaly, confidence, flow-rate,
selected stable features, and alert-rate distributions. Normalize rate and heavy-tailed
flow fields before comparison, deduplicate observations by detection UUID, and persist
deterministically identified crossings before acknowledging the detection stream.
Events are review recommendations with both automatic-action and retraining flags fixed
false. Updating a learned benign baseline from observed traffic was rejected because it
would allow suspicious traffic to poison the detector.

## D-013 — On-demand, sanitized, fail-closed explanation providers

Keep AI explanation generation outside ingestion and detection: an analyst-only incident
endpoint builds a separate endpoint-free aggregate envelope and recursively allow-lists it
before rendering. The default provider is the deterministic template. Optional remote
OpenAI-compatible Chat Completions and loopback-local compatible providers require an
explicit model and have bounded timeout, retries, rate, output, and incident-version LRU
cache. Provider configuration or runtime failure falls back visibly to the template.

Provider output remains labelled advisory text and has no route into detection, blocking,
feedback eligibility, retraining, or promotion. Sending full alert/flow records, analyst
comments, packet data, raw address history, or unencrypted/credential-bearing provider
URLs was rejected.

## D-014 — Derived, multi-signal deterministic incident correlation

Keep incident membership storage compact (`alert_ids` plus accumulated grouping reasons)
and derive rich summaries from durable alert, detection, flow, and signature rows. New
alerts consider open/investigating incidents within ten minutes and must share at least
one of: source, destination, signature, reason, a specific deterministic attack stage, or
a repeated risk/severity escalation. Time alone and generic unknown/review stage labels
are insufficient. When several incidents match, the one with the most explained matches
wins; recency breaks ties through query ordering.

This avoids a migration full of denormalized lists that could drift from the source
records. A slightly higher read cost is accepted for honest, reconstructable incident
detail and the small bounded operational/demo scope.

## D-015 — Bounded retention and purpose-specific sanitized exports

Run operational retention in the API process only after the first configured interval,
and expose the same cleanup as a one-shot command for external schedulers. Delete
foreign-key dependants first, remove empty incidents, and write success or redacted error
health events. This keeps the demo self-contained without performing surprise cleanup at
startup; larger deployments can disable the worker and schedule the idempotent command.

Exports use fixed purpose-specific column allow-lists and bounded row counts. Address
pseudonyms default on and use an ephemeral per-export HMAC salt, preserving joins within
one report without enabling durable cross-report tracking. Retraining exports contain
only analyst-approved benign-new-behaviour features in registry order. Persisting export
salts, exporting full JSON blobs, or including analyst comments/identities was rejected
because those choices add privacy risk without helping model training.

## D-016 — Bounded ingress with hash-only failure evidence

Apply independent limits at each trust boundary: 64 KiB mutation bodies, allow-listed
and connection-bounded WebSockets with 256 KiB outbound frames, 1 MiB serialized stream
messages, and a bounded Redis stream. Queue capacity is observable as utilization plus
transition counts; explicit drops have their own metric. These defaults suit the
single-host demo and remain configurable for measured deployments.

Malformed queue entries retain only source, error class, expected-field presence,
unexpected-field count, and a SHA-256 of canonical input. Copying the rejected envelope
into a dead-letter stream was rejected because attacker-controlled fields could smuggle
payloads or secrets into durable infrastructure. All service events use a fixed JSON
shape and redact addresses, credential patterns, and control characters. Operational
debug convenience does not outweigh the no-payload/no-secret invariants.

## D-017 — Reopen completion for evidence-based production readiness

Treat the green offline demonstration as a verified baseline, not as evidence of
enterprise production readiness. The expansion audit explicitly reopens semantic flow
direction, standard Community ID, exact-hybrid public-data evaluation, empirical anomaly
calibration, evidence-backed fusion, throughput/scaling, identity/RBAC, production
deployment, retraining governance, and the editorial UI. Preserving the old all-complete
claim was rejected because it would conflate a reproducible demo with an evaluated
organizational deployment.

## D-018 — Separate unordered identity from semantic traffic direction

Use standard [Community ID v1](https://github.com/corelight/community-id-spec) as the
direction-independent correlation key, while retaining initiator/responder endpoints as
separate flow semantics. Scapy chooses a TCP SYN without ACK first, then an unambiguous
ephemeral-client/well-known-service pair, then the first observed packet. NFStream keeps
its first-packet `src2dst` semantics unless the same unambiguous port evidence corrects a
mid-stream capture. A correlated Suricata flow record is authoritative when complete
`toserver`/`toclient` counters and matching endpoints are present.

Sorting endpoints and then treating the result as forward direction was rejected because
it silently changes destination-port and directional features. Treating Suricata's native
numeric `flow_id` as Community ID was also rejected; when no complete tuple exists it is
retained only as a namespaced, hashed Suricata-local identity. The standard SHA-1 digest
is used solely for protocol interoperability, never for a security decision.

## D-019 — Benign empirical CDF and calibrated interpretable fusion

Bundle schema v3 adds a checksum-covered `calibration.json` containing at most 2,049
monotonic knots from the combined anomaly scores of a benign-only grouped calibration
partition. Runtime `anomaly_percentile` is the right-rank empirical CDF estimate, while
`anomaly_score` remains the normalized decision signal. Reusing the normalized score as
a percentile was rejected because scale position is not population rank. Using observed
runtime traffic as the reference was rejected because suspicious traffic could poison it.

Keep the rule-based fusion decision, load every weight and threshold from the bundle, and
select among a bounded transparent grid on final-verdict macro F1. Report the unchanged
baseline and selected configuration on a separate grouped test partition. For smoke v3,
the selected rule retained all baseline weights and raised only the anomaly threshold from
0.70 to 0.74. This synthetic comparison proves the machinery, not operational superiority;
public held-family and cross-dataset evaluation remains mandatory.

## D-020 — One exact hybrid scorer and publish negative evaluation evidence

Use `packages.detection.hybrid.HybridPredictor` for both runtime detection and offline
public-data evaluation. Evaluation retrains the same classifier and benign-only anomaly
model families, derives calibration from a disjoint fold, and passes canonical arrays
through the same fusion implementation. CSV rows do not receive fabricated signature or
rolling-context signals. Keeping a simpler logistic-only evaluator was rejected because
it could not measure the detector actually being deployed and invited scoring drift.

Publish the sanitized official UNSW-NB15 training/testing report even though it fails
operational expectations. Its high benign false-positive rate and review volume are
decision evidence, not a marketing metric. Compare fusion configurations on the same
fixed four-verdict label set; additionally expose observed-label macro F1 only as a
diagnostic. Treating an observed-label change as an improvement was rejected because a
configuration can change which zero-support verdict labels appear and thereby change the
denominator without improving supported-class performance. The official UNSW partitions
also share every family and have substantial canonical overlap, so they do not replace
held-family or genuinely cross-dataset evaluation.

## D-021 — Preserve model-registry bytes across Git checkouts

Treat every file under `models/registry/` as a byte-preserved artifact because bundle
checksums cover exact serialized bytes, including human-readable metadata. Disable Git
text conversion for that subtree and make new training output write LF explicitly. Keep
the legacy v1/v2 byte representation intact so their historical checksums remain valid.
Relying on a developer's `core.autocrlf` setting was rejected after a Windows-generated
checksum passed locally but failed on Linux CI when checkout normalization changed JSON
line endings. A generated-bundle regression test now requires platform-independent LF
for all new text artifacts.

## D-022 — Audit invalid public-data rows instead of coercing them

Treat repeated CSE-CIC-IDS2018 shard headers as non-records and exclude CICFlowMeter rows
whose canonical features are non-finite or outside the versioned registry. Record each
reason and count in `quality.excluded_rows`, retain the untouched source checksum, and
include exclusions in the canonical dataset fingerprint. Mapping invalid rates to zero
or benign was rejected because it would hide malformed evidence and distort both the
benign baseline and false-positive measurements. Blocking the entire 328,181-row valid
partition because 2,919 rows have undefined rates was also rejected once a narrow,
auditable exclusion policy was available.

When source groups cannot separate internal calibration, use a chronological tail if
every timestamp is valid and both fit requirements and benign calibration support hold.
Only then fall back to stratified rows. This preserves time order for the reviewed CSE
file without pretending equal-timestamp shard boundaries are independent captures.

## D-023 — Public reports are rejection gates, never promotion authority

Report schema 1.1 evaluates transparent default review thresholds for observed-label
macro F1, benign false-positive rate, direct and review-assisted unknown detection,
calibration error, replay-hour false alerts, and canonical overlap. Missing measures are
explicitly not applicable. Any failed criterion rejects a candidate; even a full pass
sets `automatic_promotion_allowed` to false because all required modes and human review
remain necessary.

Freeze the published UNSW official, held-`exploits`, CSE chronological, and UNSW-to-CSE
results as final evidence. Using their severe failures to tune the same candidate was
rejected as test leakage. A future multi-source challenger needs new fit/calibration
partitions and must be compared against these reports only once its configuration is
locked.

## D-024 — Bounded hybrid and persistence batches with failure isolation

Use one exact `HybridPredictor` call for up to 64 flows, publish all resulting detection
envelopes in one atomic Redis pipeline, and acknowledge their source IDs with one command
only after publication succeeds. Malformed raw Redis JSON, a schema-invalid row, or a
feature-invalid row is hash-only quarantined and removed without poisoning valid rows. A
model-wide error is not recast as
bad input; the batch stays pending for recovery. Multiple detector processes share the
same Redis consumer group, so horizontal replicas receive disjoint work while deterministic
detection IDs preserve replay idempotency.

Persist up to 64 detections in one PostgreSQL transaction and cache derived incident
grouping context only for the lifetime of that transaction. The cache is built from durable
source rows and updated with each accepted alert; it never becomes a learned traffic
baseline. Drift events still become durable before Redis acknowledgement. Per-row model
calls, per-output `XLEN`/`XADD`, per-ID acknowledgement, per-row database commits, and
reloading an entire growing incident for every alert were rejected after the measured
2,000-flow Compose run timed out at 150 seconds with only 1,828 rows durable.

The post-change run completed all 2,000 rows in 25.39 seconds with zero queue lag. This is
mechanical single-host evidence, not a capacity guarantee; representative sustained replay
and multi-host evidence remain required.

## D-025 — Cache immutable container dependencies before application source

Install pinned CPU PyTorch, build tooling, and project dependencies before copying changing
application source into the backend image. Copy the source afterward and build the local
wheel with `--no-deps --no-build-isolation`. The first cache-establishing build still pays
the network download cost, but the measured follow-up source rebuild completed in 6.3
seconds instead of redownloading the full ML runtime. Baking dependencies after all source
copies was rejected because every code edit invalidated the most expensive image layer.

## D-026 — Explicit identity modes and server-derived hierarchical RBAC

Use three explicit API modes: local `demo` only while demo mode is enabled, OIDC bearer
validation for human/organizational identity, and a mounted file of hashed role-bearing
API keys for service accounts. OIDC requires asymmetric signatures, issuer/audience,
`sub`/`iat`/`exp`, bounded lifetime, allow-listed role mapping, and bounded HTTPS JWKS
retrieval. Apply viewer authentication to every versioned API and metrics route, then
require analyst or admin for sensitive operations. WebSockets use the same identity and
origin boundary; browser tokens travel as a subprotocol, never a query parameter.

Derive every audit actor from the authenticated subject and remove actor fields from
mutation bodies. The earlier optional shared mutation key was rejected because reads and
WebSockets stayed anonymous, every privileged client had equivalent power, and callers
could spoof audit attribution. Per-process principal limits provide a bounded local guard;
the production gateway remains responsible for a shared multi-replica limit.

## D-027 — Public evaluation rejects; independent humans authorize promotion

Register a challenger only after reloading its checksum-valid v3 bundle and hashing
sanitized schema-1.1 evaluation reports bound to that exact model/version and checksum
file digest. Require valid train/test fingerprints plus the
shared deployed hybrid scorer and grouped/source-file, chronological, held-family, and
cross-dataset coverage. A failed report, missing mode, or synthetic training fingerprint
creates a durable rejected candidate. A pass only permits review and keeps
`automatic_promotion_allowed=false`.

Store candidate/review state in PostgreSQL. Reviews are immutable, creators cannot review
their candidate, and promotion needs approval from a different authenticated identity.
Revalidate every byte immediately before atomic pointer replacement and require a
controlled worker restart; never hot-swap a model mid-batch. Emergency admin rollback
uses validated pointer history and marks the displaced candidate rolled back. Allowing an
administrator to override a failed scientific gate or letting one identity create,
approve, and promote was rejected.

## D-028 — Separate production deployment templates from verified demo evidence

Keep the base Compose profile as the reproducible loopback demo. Add a production Compose
override that forces non-demo OIDC, mounted database secrets, health/resource/log bounds,
a shared writable control-plane model volume, read-only detector mounts, and explicit
governance enablement. Add a Kustomize baseline that assumes managed PostgreSQL/Redis and
out-of-band secrets, with non-root/read-only pods, probes, disruption budgets, TLS ingress,
and ingress NetworkPolicies.

Do not describe rendered templates as a deployed platform. Target organizations must
replace invalid placeholders, use immutable signed images, validate RWX or an external
model registry, perform restore/rollout tests, and measure their own capacity. Committing
credentials, bundling a default production password, or claiming cluster readiness from
client-side rendering was rejected.

## D-029 — Resolve the database secret once for runtime and migrations

Use one bounded `database_url_from_env` loader for both SQLAlchemy runtime construction
and Alembic. A mounted `AEGISFLOW_DATABASE_URL_FILE` takes precedence over the environment
URL, must contain one nonempty UTF-8 line, and is never logged. Alembic escapes literal
percent signs only when writing the value into its ConfigParser and otherwise preserves
the URL. A fresh-database integration test upgrades through the governance migration using
only the mounted secret file.

Duplicating URL resolution in `migrations/env.py` was rejected because production Compose
could start the application with one credential source while migrations silently used the
demo environment fallback. Keeping a nullable ConfigParser default was also rejected
because it weakened strict typing at the deployment boundary.

## D-030 — Serialize migrations and schedule retention once per cluster

Run schema upgrades through `scripts.migrate`, which uses a stable PostgreSQL session
advisory lock around Alembic while retaining a direct path for SQLite development. This
makes simultaneous API init containers wait rather than race DDL. The database URL still
comes from the shared secret loader and is never printed. Both Compose and CI exercise the
same entry point, and focused tests prove a fresh secret-file upgrade plus lock/upgrade/
unlock ordering.

Disable the in-process retention thread in the replicated Kustomize API and assign cleanup
to one daily CronJob with `concurrencyPolicy: Forbid`; expose that external mode and its
operational/audit windows in system status. Running Alembic or retention independently in
every replica was rejected because rendering two valid pods does not make concurrent DDL
or duplicate schedulers reliable.

## D-031 — Re-resolve the API upstream after container replacement

Configure the unprivileged dashboard Nginx with Docker's embedded DNS resolver and a
shared-memory upstream using `resolve`. This lets the loopback Compose dashboard survive
an API container replacement instead of retaining the removed container's IP and serving
502 responses. CI force-recreates only the API, waits on the dashboard-proxied readiness
route, and then runs Playwright.

Restarting the dashboard whenever the API changes was rejected because it hides a stale
service-discovery defect and makes otherwise independent frontend availability depend on
backend container identity. Kubernetes ingress routes `/api` and `/health` directly to
the API Service, so its cluster DNS remains outside this Docker-specific proxy path.

## D-032 — Treat the dashboard as a network-intelligence brief

Use a light-first mineral editorial system for the seven analyst views: deep ink and
paper surfaces, patina/danger/evidence accents, Georgia display hierarchy, Segoe UI/Aptos
working copy, and Cascadia Mono measurements. Keep one distinctive dark live-signal
ribbon and an asymmetric overview lead; use quiet shared cards everywhere else. Replace
decorative navigation numbers with labels that describe each view's actual job. Preserve
the same hierarchy in automatic dark mode and collapse it deliberately for tablet and
mobile widths.

Make accessibility an executable acceptance condition. Chromium scans the overview,
every analyst view, and the evidence dialog with Axe and requires zero violations. The
same path verifies the skip link, current-page state, dialog labelling/autofocus, and
Escape dismissal. A generic dark SOC-console restyle and a warm lifestyle-editorial
theme were rejected because neither expresses the requested newsroom intelligence
character without obscuring operational evidence.

## D-033 — Freeze legacy public evaluations before challenger research

Treat the four committed UNSW/CSE reports as immutable, final-only rejection evidence.
Record each report byte hash, a versioned canonical hash of evaluation inputs and gate
policy, embedded source-file hashes and sizes, publication commit/time, and permitted use
in `configs/evaluation/frozen-evidence-v1.json`. Verify the boundary in CI and fail closed
if a report, its evaluation configuration, its source fingerprints, or the no-development-
use policy changes. Preserve the original failing outcomes and automatic-promotion=false.

The configuration projection intentionally excludes observed scores, predictions, and
criterion pass/fail values while binding the dataset/split, bundle identity, feature order,
fit manifest, seed, shared inference path, row counts, dataset fingerprints, class scope,
and gate thresholds. This separates configuration integrity from result bytes while the
full report hash protects both. Re-running, editing, or mining the frozen reports during
challenger development was rejected because it would convert final evidence into a tuning
set and invalidate the acceptance claim.

## D-034 — Add research schemas without breaking the frozen bundle contract

Keep the deployed 18-feature registry unchanged for legacy bundle reproducibility. Add
Schema A as an exporter-independent flow representation and Schema B as Schema A plus
bounded AegisFlow-owned temporal behavior. Use the same pure vectorizer and state machine
from runtime `FlowEvent` conversion and training dataset replay. Treat missing temporal
prerequisites as schema unavailability, not as a zero-filled behavioral history.

Schema A replaces raw magnitudes with log/fraction fields and replaces continuous port
distance with explicit missingness, port-range, protocol, and service-family categories.
Schema B keys state by sensor+source, expires it, caps sources/events/duplicate history,
returns cached vectors for duplicates, and flags late traffic while ignoring events beyond
the skew allowance for state mutation. Train-only quantile clipping and robust scaling are
serialized separately so evaluation rows cannot change preprocessing. Replacing the
production bundle before development evidence, silently fabricating temporal context, and
using a vendor CSV's similarly named field without semantic review were rejected.

## D-035 — Admit only reviewed fresh sources and block origin shortcuts

Build the first development pool from the official HIKARI-2021 v1.4.0 Zenodo artifact and
the official CSE-CIC-IDS2018 February 28 processed object. Bind reviewed local SHA-256,
publisher metadata, license/citation notes, capture limits, exclusions, class counts, and
sanitized quality fingerprints in a versioned manifest. Refuse preparation or diagnostics
when any input hash matches the frozen-final manifest. Raw files remain ignored.

Treat absent temporal prerequisites as unavailable, not as fabricated context. HIKARI's
aggregate file lacks a trustworthy row timestamp and protocol; the processed CSE file
lacks endpoints. Neither may claim Schema B evidence. The first origin classifier obtains
1.000 balanced accuracy on full Schema A, driven by protocol availability, so that feature
view is blocked. Its categorical ablation reaches 0.69772 and may be researched further,
but cannot be selected until broader grouped evidence exists. Using mirrors, bypassing an
official access form, zero-filling temporal history, or treating an S3 multipart ETag as a
file MD5 were rejected.

## D-036 — Use a bounded official IoT-23 slice for temporal development evidence

Add six checksum-reviewed IoT-23 IndividualScenarios Zeek flow logs from the official CTU
repository: four small malicious captures (Mirai, Torii, Trojan, and Hakai) plus two real
benign-device captures (Philips HUE and Amazon Echo). Keep each object as a source group
and treat the combined CTU environment as one dataset origin. This provides 43,009 flows,
five normalized behavior labels, and full timestamp/endpoint/protocol/port coverage
without downloading multi-gigabyte scenarios.

Use Zeek `orig_ip_bytes`/`resp_ip_bytes` as directional wire-byte semantics. Represent an
unset duration as zero observed milliseconds and derive rates with a one-microsecond floor;
represent zero-packet mean length as zero. The legacy bundle-compatible vector uses port
zero only when Zeek has no transport port, while research Schema A retains explicit port
missingness. Raw endpoint identity is used only transiently by the bounded Schema B state
machine and excluded from model vectors and committed evidence. Dropping 14,260 mostly
DDoS zero-packet flows, flattening all captures into one group, or downloading the full
21+ GiB corpus were rejected because each would weaken validity without helping the next
experiment.

## D-037 — Start challenger research with an untuned numerical-core baseline matrix

Begin A3 with binary benign-versus-malicious cross-environment baselines over the
nine-feature numerical core that cleared the dataset-origin threshold. Compare class-
weighted logistic regression, sigmoid-calibrated random forest, class-weighted
HistGradientBoosting, and the existing-size compact MLP in all three leave-one-environment-
out rotations. Use train-fit quantile clipping/robust scaling, a fixed 0.5 decision
threshold, and report F1, PR-AUC, benign FPR/workload, recall, ECE/Brier, latency,
throughput, memory, and exact cross-source feature overlap.

Require a clean committed tree before an experiment so its code hash is meaningful.
Deterministically cap each binary class per source, remove exact duplicates, and remove
feature vectors carrying conflicting binary labels while recording every index hash and
count. Commit only aggregate evidence, never predictions or endpoint identities. XGBoost
or LightGBM is deferred until the dependency provides measurable benefit over maintained
scikit-learn baselines; advanced open-set models and threshold selection remain separate
experiments. Running the frozen reports, optimizing a threshold during this baseline, or
calling binary maliciousness an unknown-behaviour result were rejected.

## D-038 — Separate anomaly fit, threshold calibration, and held environment

Evaluate benign-only Isolation Forest, robust covariance, Local Outlier Factor novelty,
one-class SVM, and a compact CPU denoising autoencoder with a strict three-way environment
rotation. One fresh environment supplies benign fit rows, a second supplies only benign
threshold calibration, and the third remains wholly held out. Repeat both fit/calibration
orientations for every held environment, yielding six runs per model. No attack label or
attack row enters anomaly fit or calibration, so every tested attack family is genuinely
unseen by the anomaly model.

Set direct-suspicious thresholds at a 1% calibration benign-FPR budget and review
thresholds at 5%; report the observed calibration rate, transferred test FPR, direct
unknown recall, detection-or-review, per-family results, PR/ROC AUC, score percentiles,
resource cost, and a four-point operating curve. Keep the numerical-core feature view and
train-fit preprocessing from the origin-cleared baseline. Do not report false alerts/hour
from class-sampled/deduplicated data. Combining fit and calibration environments, fitting
on attacks, interpreting anomaly scores as calibrated probabilities, or hiding a model
fit failure were rejected.

## D-039 - Test temporal contribution with disjoint benign capture calibration

Use the two all-benign IoT-23 device captures as anomaly fit and threshold-calibration
environments, repeating both orientations. Fit the supervised head on HIKARI and the fresh
CSE day after removing every row of the held family. Test command-and-control, DDoS, and
port-scan separately using all family rows plus benign rows from their attack capture
groups; exclude the three file-download rows from quantitative claims.

Compare supervised-only, anomaly-only, context-only, pairwise combinations, the full
hybrid, no-temporal, and no-port-context views. Divide each total calibration FPR budget
equally across signals before OR fusion so a hybrid does not silently double its budget.
Treat the binary supervised score as maliciousness evidence rather than proof of a known
family, and let direct anomaly evidence account for `suspicious_unknown`. IoT-23 supplies
no replay-correlated signature evidence, so signature ablations remain visibly not
evaluable. Random row splits, using attack-capture benign rows for calibration, including
the held family in supervised fit, and inventing signature results were rejected.

## D-040 - Keep error analysis aggregate and development-only

Rerun the fixed held-family protocol solely to group false positives and missed malicious
rows by fixed semantic categories: protocol, service, duration, packet count, direction,
host behavior, temporal state/missingness, and signal disagreement. Suppress categories
with fewer than five rows and retain only counts and rates. Do not serialize endpoints,
row IDs, individual scores, or per-row decisions.

Use the result to choose one predeclared next direction: cross-fitted environment-aware
benign calibration. This uses both approved benign device captures while ensuring each
calibration score comes from a model that did not fit that row. Treating attack-capture
traffic as approved benign, mining frozen-final errors, storing row-level diagnostics, or
shifting thresholds separately for each held family were rejected.

## D-041 - End the current challenger search with a development NO-GO

Use cross-fitted benign-device calibration as the final predeclared experiment for the
current feature/model family. Fit one anomaly model per approved benign capture, score
each capture only with the model fitted on the other, convert scores to empirical
percentiles, and use their mean as the primary site anomaly signal. Keep min/max
aggregation as sensitivity analysis only; it cannot replace the mean after test results
are visible.

Because the primary configuration fails the development recall and transferred-FPR
objectives, do not lock it and do not run the frozen final matrix. Record a development
scientific NO-GO and preserve the frozen boundary. Searching more algorithms over the
same low-observability fields, selecting the better min/max result post hoc, lowering
gates, or spending frozen evidence on an ineligible candidate were rejected.

## D-042 - Fail sustained capacity closed on conservation, lag, and latency

Measure the durable Redis-to-PostgreSQL path with paced, metadata-only local Compose
traffic rather than extrapolating from the existing burst-drain result. A rate is
sustainable only when at least 98% of the requested pace is maintained, published and
durable flow/detection counts match exactly, both queue depths stay within the declared
budget without positive second-half growth above a 2% rate tolerance, durable P95 latency
meets its declared budget, and both consumer groups return to zero pending plus lag.

Keep every service URL restricted to localhost or the AegisFlow Compose network and retain
only aggregate measurements. Write the report even for a NO-GO and exit nonzero so
automation cannot confuse partial persistence or an undrained queue with capacity.
Treating a short burst, eventual drain after unbounded growth, or publisher throughput
alone as sustainable capacity was rejected.

## D-043 - Exercise OIDC with an optional disposable Dex profile

Add a local-only Dex 2.44.0 profile that is separate from production Compose and uses a
generated seven-day CA, generated static-user passwords, public acceptance clients, and a
tmpfs SQLite store. Map the signed email claim through AegisFlow's explicit role allow-list
to exercise viewer, analyst, and admin behavior without pretending the fixture represents
an organizational directory. Keep every plaintext credential and private key under the
ignored `.runtime/oidc` directory and never include either in the aggregate report.

Use the password grant only for non-interactive local acceptance; production clients must
use authorization code with PKCE. Require the drill to cover token issuance, discovery,
JWKS/TLS, issuer/audience/lifetime checks, roles, escalation denial, WebSockets, rate
limits, audit attribution, key rotation, and expiry. Making Dex a production dependency,
committing static passwords, using cleartext non-loopback identity traffic, or claiming
that a local fixture validates a target organization's IdP were rejected.

## D-044 - Normalize incident membership before claiming sustained capacity

Replace the growing `incidents.alert_ids` JSON write path with an indexed
`incident_alerts` membership table. Backfill existing membership in a reversible migration,
keep API alert-ID and timeline responses derived from the normalized rows, and retain only
compact grouping aggregates plus the two most recent risk/severity values needed for
escalation. Explicitly flush a newly created incident before its membership row because
table foreign keys alone do not guarantee ORM unit-of-work order without relationships.

Use AOF as the sole automatic persistence mechanism for the local Compose Redis service
and disable default RDB schedules there; target deployments must define their own managed
Redis backup policy. This avoids a dual-persistence disk spike turning a full Docker disk
into a write outage while preserving fail-visible AOF errors. Increasing queue budgets,
disabling Redis write safety, deleting pending work, treating post-timeout drain as a pass,
or claiming the 10-minute local result as production capacity were rejected.

## D-045 - Treat long-run conservation and capacity as separate gates

Retain the 30-minute 50 flows/s result as a capacity NO-GO even though all 90,000 flows
and detections eventually became durable and both queues returned to zero. The run fails
the predeclared P95 latency, maximum queue-depth, and second-half growth budgets and also
contains one unplanned API process kill followed by successful automatic recovery.

Use it to bound the current local evidence envelope and to demonstrate fail-visible
restart recovery. Do not reinterpret eventual drain as sustainable service, hide the
host-contention limitation, raise the budgets after seeing the result, or generalize the
passing 10-minute point to longer windows. Establish any lower 30-minute rate through a
separate predeclared run.

## D-046 - Reconcile multi-worker latency by event identity

Exercise persistence replicas with a paced local workload and a controlled SIGKILL only
after Redis proves the acceptance worker owns pending messages. Require durable work from
the initial replica, surviving primary, and restarted replica; reclaim after the configured
idle boundary; exact planned/published/flow/detection conservation; and zero final depth in
both consumer groups. Keep the workload metadata-only and treat this as correctness and
recovery evidence, not a multi-host or scaling-capacity claim.

Track observed durable latency by event identity and perform one final all-run
reconciliation query. Fail the sustained verdict when the latency-sample count differs
from the published count. A timestamp-only high-water cursor was rejected because an
abandoned older batch may commit after newer rows on another worker: database conservation
can remain exact while that cursor silently omits the late observations.

## D-047 - Make production preflight an evidence and deployment gate

Validate production configuration from the release workspace before deployment and fail
on any unsafe identity, secret, browser-origin, external-provider, datastore-exposure,
filesystem, capability, model, readiness, retention, or backup state. Reuse the governed
candidate evaluator for exact bundle/report binding and require a separate release-time
approval attestation whose approver differs from its promoter. Never print secret values.

Treat the checked-in scientifically rejected smoke bundle as an intentional production
NO-GO. A successful Compose render, checksum-valid bundle, or passing scientific report
alone is insufficient: operational ownership and human approval must also be explicit.
Permissive defaults, accepting fallback models, inferring retention ownership, or treating
documentation as proof of a backup were rejected.

## D-048 - Restore only inside an isolated disposable Compose project

Exercise backup restoration in a dedicated `aegisflow-restore-acceptance` Compose project
whose PostgreSQL and Redis volumes are project-scoped. Refuse to start if any container or
volume with that project label already exists. Seed deterministic synthetic metadata,
record per-table counts and primary-identity digests, create a custom-format `pg_dump`,
force-drop only the disposable database, restore into a clean database, re-run migrations,
compare every table and identity digest, and smoke the real API before deleting the dump
and project volumes.

Run the destructive sequence on a clean CI runner when the local host is under unrelated
memory pressure. Retain only aggregate counts, timings, and the backup SHA-256; never
retain the dump or emit credentials. Reusing the developer database, dropping a database
without a project-isolation check, treating `pg_restore` exit zero as sufficient, or
claiming managed-backup readiness from this local drill were rejected.

## D-049 - Exercise the production Kustomize base through a demo-only kind overlay

Keep the organizational Kustomize base free of databases, credentials, demo identity,
and mutable image tags. Compose it into a separate local-acceptance root that adds only
disposable PostgreSQL/Redis, generated secrets and TLS, local images, and zero initial
application replicas so model volumes can be seeded before migration-bearing pods start.
Run the profile in a fixed-name kind cluster and refuse to replace any cluster already
using that name.

Require actual TLS ingress, probes, resource bounds, migration init, two-replica API/
dashboard/detector startup, safe sensor replay, exact database conservation, enforced
data-service NetworkPolicy denial, API rolling replacement, detector scale and pod
replacement, idempotent replay, and exact cleanup. Use cluster DNS as the dashboard's
configurable resolver while preserving Docker's resolver default. Treat this only as
single-node deployment-mechanics evidence. Editing the production base into a demo,
committing test secrets, applying traffic externally, replacing an existing cluster, or
calling a local kind result managed-cloud readiness were rejected.

## D-050 - Support one organization and one security domain per deployment

Declare AegisFlow single-organization, single-security-domain software. Viewer, analyst,
and admin roles separate duties inside that domain; they do not partition database rows,
streams, metrics, model registries, audit history, exports, or encryption keys by tenant.
Operators needing mutually untrusted tenants must deploy isolated instances with separate
identity audiences, secrets, data services, registries, gateways, backups, and audit
ownership. Inferring tenant isolation from RBAC or adding an untested `tenant_id` field
without end-to-end policy enforcement were rejected.

## D-051 - Bind release evidence even when the scientific verdict is NO-GO

Build both container images from a clean commit, generate CycloneDX SBOMs with a pinned
checksum-verified Syft binary, and emit one aggregate manifest binding application/commit,
local immutable image content IDs, SBOM hashes, Alembic head, model/checksum manifest,
feature schema, Suricata/rules, configuration validator, and dependency locks. Preserve
the scientific eligibility in the same artifact so mechanically reproducible images
cannot be mistaken for an approved detector.

Require registry digests and external signing/transparency evidence from the actual
release owner before deployment. Committing large SBOMs, inventing registry digests,
declaring a release GO from image builds, or omitting the rejected-model status were
rejected.

## D-052 - Run the next sustained point at 30 flows/s on a clean Linux runner

Predeclare a separate 30-minute 30 flows/s point after the local 50 flows/s 30-minute
NO-GO. Keep the existing acceptance semantics and budgets unchanged: at least 98% of
requested ingress, exact published/flow/detection conservation, 5-second durable P95,
10,000 maximum queue depth, second-half growth within the two-percent rate tolerance,
and zero final pending plus lag. Retain and publish the report even when it fails.

Use a clean disposable GitHub-hosted Linux runner because unrelated workstation memory
pressure invalidates another local capacity attribution. This does not make hosted-runner
hardware representative of a target deployment; it supplies a reproducible lower-rate
point and recovery/conservation evidence. Raising observed budgets, overwriting the
50-flows/s failure, or treating eventual drain as a pass were rejected.

The first invocation exited before publishing traffic because `docker compose up -d`
returned while the API migration command was still creating the schema. Treat that as an
invalid startup attempt, add `/health/ready` to the base Compose contract, and require the
benchmark target to wait for readiness. Do not change the predeclared rate, duration, or
budgets in response.

The second invocation completed the 30-minute workload and reconciliation but failed while
creating the report in the Linux bind mount because the non-root container could not create
a file in the runner-owned directory. Treat that as another invalid evidence-retention
attempt. Validate a basename-only JSON output and pre-create exactly that file with write
permission before starting the container; do not run the benchmark as root, broaden the
directory permissions, recover a verdict from incomplete logs, or alter the declared point.

## D-053 - Treat ingress admission readiness as a retryable apply condition

The pinned kind ingress manifest ships its two admission-certgen jobs with
`ttlSecondsAfterFinished: 0`, so a completed job is garbage-collected almost
immediately; `kubectl wait --for=condition=complete` therefore races TTL deletion and
can fail with NotFound even when everything succeeded. The deterministic sequence is:
apply the pinned manifest, wait for the controller pod readiness condition, then apply
the AegisFlow overlay through a bounded retry that re-runs only on the transient
"failed calling webhook"/"connection refused" class of errors, because server-side
manifest application is declarative and converges on re-apply. Waiting for ephemeral
job objects, deleting the webhook from the profile, or retrying every failure class
unboundedly were rejected.

## D-054 - Separate archive integrity from scientific and project acceptance

The 2026-09-02 audit rejects the earlier blanket closure claim. HF1/HF2 retain C&C in
fit, FAMILY/DANN share site captures with fitting, learned embeddings exceed the 0.90
origin threshold, and per-run v2 provenance is incomplete. Preserve the old artifacts as
historical observations and require corrected experiments before scientific acceptance.
The final brief also requires deployed site-baseline activation and specific rollback
drills. Track those as repository work in `docs/REQUIREMENTS_AUDIT.md`.

Bind the v2 record with `configs/research-v2/protocol.json` and
`configs/research-v2/evidence-manifest.json`; enforce the boundary through
`scripts/verify_research_v2.py`, `make research-v2-check`, and the Python CI job. The
manifest records publication provenance, six source hashes, five aggregate reports,
and six row-level embedding archives. It is an integrity guard, not proof that the
experiments obeyed their protocol. Text digests normalize only CRLF to LF so Windows
and Linux verify the same Git content. Reconstructed policy metadata is dated when
created; it must not imply a pre-experiment registration that did not exist. Preserve
the user's pre-existing model-registry edits and all original report bytes.

## D-055 - Enforce whole-label-family and calibration isolation before training

HF1/HF2's historical malware-capture transfers are not held-family experiments. Corrected
FAMILY rotations hold out each of C&C, DDoS and port scan, calibrate on hp4 benign rows,
and use hp5 only for independent benign testing. The guard rejects held-family fitting,
site-capture reuse, duplicated event IDs/observations, empty partitions and non-benign
calibration. It allows other attack families from the same malware capture in fit:
that is whole-family evaluation, not a claim of whole-environment exclusion.

DANN's hp4 site pool is removed from fitting and testing; Mirai incidental benign
performance is reported separately from site calibration. Seed Torch before construction,
not just its data loader. Unknown binary labels must raise rather than become benign.
FAMILY/DANN corrected diagnostics go to ignored, exclusive-create local files and remain
unregistered until actual commit/data/split/configuration/cost provenance is supplied.
No old metrics are reinterpreted as new results; final evaluations stay sealed.

## D-056 - Bind preparation to executed clean code and reject ambiguous labels

The historical summary covers only three of the six prepared scenarios. Do not infer
the preparation commit from a publication commit or merely stamp the existing rows.
Regenerate into a new ignored evidence directory from an isolated clean Git worktree,
verify every PCAP/label pair against the pinned pool before and after replay, record
the executed commit and environment, and bind every output file and count. This keeps
the user's uncommitted model/demo files untouched without weakening the clean-code gate.

A synthetic regression shows the old interval join chooses the first label when a
coalesced five-tuple spans contradictory ground truth. Reject and count such ambiguous
joins instead of choosing benign or a convenient family. Same-label overlap is retained;
this is still a coalesced-flow research representation, not per-Zeek-connection parity.
Use exclusive creation for prepared evidence. Incompatible JSONL rows must be visible
errors, not silently skipped. No final acceptance data enters this preparation.

## D-057 - Budget tied groups and deduplicate the evaluated representation

A constant benign score at its percentile cut causes every row to be flagged with `>=`.
Use the next representable value above the first excluded score group, preserving exact
cuts in reports. Split the registered direct budget across known/OOD channels (0.5% each)
and the review-inclusive budget (2.5% each). Reference-budget control is not an independent
benign FPR guarantee; measure both site orientations without threshold retuning.

The old raw-field fingerprint omitted service inputs. A read-only comparison found a
249-row old-fingerprint group spanning three labels, but its actual model tensors differ.
Actual sequence/mask/aggregate deduplication yields 6,674 inputs with no contradictory
labels, versus 6,671 from the old fingerprint. Reject true identical-input conflicts.
Register the exact protocol and clean preparation manifest before corrected execution;
do not reinterpret legacy diagnostics as registered runs. Models stay local and unpromoted.

## D-058 - Preserve the corrected strict-family negative result without retuning

`DEV2-FAMILY-002` ran all six preregistered rotations from clean code `3659031`.
C&C and DDoS have zero detection/review; worst independent benign FPR is 47.51%.
Port-scan results involve only four distinct inputs, with known-channel detections
separated from direct unknown recall. Same-family artifacts are identical across site
orientations, isolating calibration-site sensitivity from model reinitialization noise.

Preserve the full report and numeric artifact hashes. Do not alter the declared budgets,
rerun to find a favorable seed, or treat this development rejection as the brief's final
Outcome B. Next research must address benign-site diversity, effective held-family sample
support, learned-embedding origin leakage and the remaining representation ablations.
The deployed approved-baseline and specific failure-drill requirements remain open.

## D-059 - Audit origin on benign captures excluded from encoder fitting

Preregister `DEV2-ORIGIN-002` against the immutable FAMILY-002 artifacts. Use only benign
hp4/hp5/20-1 rows (181/181/30), none present in encoder fitting. This controls attack
prevalence and encoder exposure while testing the observed site sensitivity. Compare
eight declared raw/ablated/frozen-embedding views and four train-fold-only numeric
transforms. Group exact evaluated vectors so repeats never cross probe folds; preserve
cross-origin ambiguity, and report infeasible grouped folds instead of changing the split.
All transformations preserve binary/categorical dimensions. No detector is retrained or
candidate selected, and this narrow origin probe cannot prove cross-domain detection.

During this audit, a regression showed the legacy origin CLI could reach data loading
before noticing an existing historical report. Add early refusal and exclusive creation,
as for the other archived entry points. Preserve the old report bytes.
