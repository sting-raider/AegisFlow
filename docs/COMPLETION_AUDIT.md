# Completion audit

This matrix maps the authoritative build brief to repository evidence. A requirement is
marked complete only when implementation and proportionate verification both exist.

| Area | Current evidence | Status / remaining work |
|---|---|---|
| Upstream audit and attribution | `UPSTREAM.md`, `docs/UPSTREAM_AUDIT.md`, Apache-2.0 root license | Complete |
| Canonical contracts | Pydantic v2 contracts and generated JSON-schema contract tests | Complete |
| Demo and PCAP sensor modes | Deterministic fixtures, bounded Scapy PCAP reader, replay tests | Complete |
| Live/NFStream extraction | NFStream 6.6.0 completed-flow adapter; two-flow bounded PCAP test; one-flow non-root Linux loopback test; dedicated `NET_RAW` image target; Windows fallback | Complete |
| Suricata | Pinned replay/live profiles; real isolated replay; six-type allow-listed parser; partial-line errors; bounded dedupe; health; correlation; checksum-pinned rule updater | Complete |
| Feature parity | Versioned fixed registry, serialized scaler, parity/range tests, 256 deterministic randomized valid-flow parity/identity trials, nonfinite and boundary rejection | Complete for current 18-feature schema |
| Supervised model | Grouped holdout compares logistic regression, random forest and MLP; selected classifier uses grouped-fold sigmoid calibration; bundle records per-class/macro/weighted, PR/ROC-AUC, calibration, confusion, importance and single/batch CPU latency | Complete for deterministic smoke scope; the public-data gate is implemented but no external score is claimed without reviewed files |
| Unknown/open-set model | Benign-only Isolation Forest plus benign-only PyTorch denoising autoencoder, validation-tail normalization, reason-coded fusion and synthetic novelty evaluation | Complete for deterministic smoke scope; held-family/cross-dataset gates are implemented but external scores are not bundled |
| Model bundles | V1 recovery compatibility; v2 complete checksums and artifact hashes; schema/order validation; atomic promotion/history; explicit rollback and visible previous-valid fallback | Complete |
| Dataset tooling | Official-source catalog; hardened provenance downloader; CIC-IDS2017/CSE-CIC-IDS2018/UNSW-NB15/NFStream adapters; quality/leakage/overlap/drift reports; time/day/source/family/cross-dataset evaluation gate | Complete; no production-quality public-dataset scores are claimed until users supply reviewed files |
| Risk fusion | Versioned configurable weights/thresholds and boundary tests | Complete |
| Drift | Bounded runtime monitoring of anomaly/confidence/flow-rate/three stable features/alert-rate; deterministic persisted events; API/dashboard; count/magnitude metrics; explicit no-action/no-retraining gates | Complete |
| Analyst feedback | Immutable original result, eligibility gate, audit entry, endpoint-free fixed-feature retraining-candidate query/export | Complete |
| Incidents | Deterministic time-bounded correlation on same source, shared destination, common signature, common reason, specific attack stage, and repeated escalation; time alone is insufficient; stored explainable reasons; derived source/destination/signature/reason/stage summaries; escalation count; chronological detail with alerts; dashboard timeline and status controls; pure-rule and repository/API/UI evidence | Complete |
| Explanation layer | Deterministic template; recursive allow-list/address redaction; endpoint-free aggregate context; remote OpenAI-compatible and loopback-local providers; explicit model; HTTPS/loopback validation; timeout/retry/rate/output bounds; incident-version LRU; injection boundary; fallback; on-demand API/metrics/UI; AI/deterministic labels; focused provider/API/UI tests | Complete |
| Database/retention | All minimum tables, indexes, UUID idempotency, scheduled/one-shot cleanup, dependency-safe retention, health writes, allow-listed exports with default per-export address pseudonyms, seed data, and concrete backup/restore procedure | Complete |
| API | Required endpoint paths, auth, safe CORS, bounded pagination, UTC date/severity/verdict/protocol/host filters, acknowledgement, structured/redacted global errors, correlation IDs, bounded safe exports, retraining candidates, rich incident/system responses, and REST/WebSocket tests | Complete |
| Dashboard | Seven responsive/keyboard-accessible views; real overview analytics; alert pause/filter/ack/evidence/feedback; incident timeline/status/notes/explanation; paginated filtered flow detail and selected sanitized export; host risk/activity/protocol/history; model metrics/score/drift/errors; live backend throughput/drop/latency/signature/Suricata/queue/retention/health depth; rendered desktop/mobile QA and four UI tests | Complete |
| Security | Threat model; HTTP/stream/WebSocket size and connection limits; safe correlations/origins; bounded queues and capacity transitions; hash-only dead letters; redacted JSON logs; local ports; non-root/read-only containers; CI scans | Complete |
| Observability | All brief-listed flow/signature/detection/alert/inference/processing/queue/model/WebSocket/drift/database Prometheus metrics; system telemetry; structured redacted JSON sensor/detector/API/access/runtime events | Complete |
| Resilience | Durable acknowledgement, retries, pending recovery, real Compose restart matrix, previous-valid model fallback | Complete |
| Automated tests | 93 Python tests plus four Vitest interactions and Playwright E2E; randomized feature parity/bounds; Redis/PostgreSQL recovery; migration/model fallback/Compose fault injection; bounded-queue performance conservation/resource test | Complete |
| Demo and commands | Required Make targets, offline Compose demo and cleanup | Complete |
| CI/CD | Python/frontend/Compose/integration/migration/audit/Trivy/gitleaks jobs | **Incomplete:** publish the final hardening milestone and verify its remote run |
| Documentation | Required topic files, current desktop/mobile screenshots, README validation snapshot, measured limitations, demo and faculty sequence | Complete |
| GitHub publication | Public `sting-raider/AegisFlow` repository and `main` default branch | Complete; final remote run still tracked under CI/CD |

The project is not complete while any row is marked incomplete. `docs/PROGRESS.md` must
remain consistent with this matrix as work lands.
