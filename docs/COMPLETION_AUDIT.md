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
| Automated tests | 128 Python tests plus four Vitest interactions and Playwright E2E; randomized feature parity/bounds; malformed Redis quarantine; Redis/PostgreSQL recovery; migration/model fallback/Compose fault injection; bounded-queue performance conservation/resource test | Complete |
| Demo and commands | Required Make targets, offline Compose demo and cleanup | Complete |
| CI/CD | Python/frontend/Compose/integration/migration/audit/Trivy/gitleaks jobs; public run `30703942894` passed every job for hardening commit `fd25b15` | Complete |
| Documentation | Required topic files, current desktop/mobile screenshots, README validation snapshot, measured limitations, demo and faculty sequence | Complete |
| GitHub publication | Public `sting-raider/AegisFlow` repository and `main` default branch | Complete |

The matrix above records completion of the original offline-demonstration brief. A new
production-readiness expansion was accepted on 2026-08-01 and supersedes the old stop
condition. The repository must not be described as production-ready while any row below
is incomplete.

| Production-readiness expansion | Current evidence | Status / remaining work |
|---|---|---|
| Semantic flow direction | Unordered canonical identity is separate from initiator/responder semantics; Scapy uses SYN/service-port/first-packet evidence, NFStream preserves or safely corrects `src2dst`, and complete Suricata `toserver`/`toclient` evidence takes precedence; focused unit/integration tests cover reversed and mid-stream cases | **Complete** |
| Community ID interoperability | Standard Community ID v1 implementation passes published Corelight TCP/UDP/IPv6 vectors; pinned Suricata 8.0.6 and Scapy emitted the exact same two IDs for the bundled PCAP; strict ID correlation precedes bounded tuple/time fallback | **Complete** |
| Exact hybrid public-data evaluation | `evaluate_dataset` retrains the deployed classifier/anomaly families and uses the shared runtime `HybridPredictor`; sanitized official UNSW split, held-exploits, CSE chronological, and UNSW-to-CSE reports cover four verdicts, calibration, leakage, latency, replay-hour, provenance, and limitations | **Complete as an evaluation harness; all four reports fail readiness and block model promotion** |
| Open-set calibration | Bundle v3 persists a bounded benign-calibration empirical CDF; source-group or chronological calibration remains disjoint from final test; public held-family direct unknown detection is 2.1% and cross-dataset anomaly percentiles saturate | **Implementation complete; operational quality failed and requires a reviewed challenger** |
| Evidence-backed fusion | Every weight/threshold loads from the bundle; synthetic selection plus public baseline/deployed comparisons are reported on fixed verdict labels; public results show no consistent operational advantage | **Evaluation complete; retain the interpretable baseline and do not claim or promote superiority** |
| Performance and scaling | Exact stage profiling; 64-row hybrid inference; atomic Redis batch publication and acknowledgement; 64-row PostgreSQL transactions; incident-context query cache; hash-only row isolation; 2,000-flow local and full-Compose artifacts; two-detector partition smoke; restart recovery from preserved pending work | **Materially stronger and measured on one host; sustained multi-hour, representative traffic, server tracing, multi-host orchestration, and deployment-specific capacity evidence remain incomplete** |
| Enterprise access control | Optional shared mutation API key only; reads and WebSockets are unauthenticated | **Incomplete:** authenticated identities, admin/analyst/viewer RBAC, audit attribution, rate limits, and OIDC-ready boundary |
| Production deployment | Hardened single-host Compose demo and operational notes exist | **Incomplete:** production topology/config, TLS proxy guidance, orchestration manifests, rollout/release evidence |
| Editorial analyst experience | Functional seven-view dark operations UI exists | **Incomplete:** reusable editorial design system, cohesive view transformation, accessibility and rendered QA |
| Retraining governance | Immutable feedback, reviewed candidate export, bundle promotion/rollback exist | **Incomplete:** champion/challenger review and explicitly authorized promotion workflow |

This expansion audit and `docs/PROGRESS.md` must remain consistent as evidence lands.
