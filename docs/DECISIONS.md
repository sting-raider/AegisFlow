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
