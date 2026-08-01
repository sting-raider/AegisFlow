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
| Feature parity | Versioned fixed registry, serialized scaler, parity/range tests | Complete for current 18-feature schema; property coverage needs expansion |
| Supervised model | Grouped holdout compares logistic regression, random forest and MLP; selected classifier uses grouped-fold sigmoid calibration; bundle records per-class/macro/weighted, PR/ROC-AUC, calibration, confusion, importance and single/batch CPU latency | Complete for deterministic smoke scope; the public-data gate is implemented but no external score is claimed without reviewed files |
| Unknown/open-set model | Benign-only Isolation Forest plus benign-only PyTorch denoising autoencoder, validation-tail normalization, reason-coded fusion and synthetic novelty evaluation | Complete for deterministic smoke scope; held-family/cross-dataset gates are implemented but external scores are not bundled |
| Model bundles | V1 recovery compatibility; v2 complete checksums and artifact hashes; schema/order validation; atomic promotion/history; explicit rollback and visible previous-valid fallback | Complete |
| Dataset tooling | Official-source catalog; hardened provenance downloader; CIC-IDS2017/CSE-CIC-IDS2018/UNSW-NB15/NFStream adapters; quality/leakage/overlap/drift reports; time/day/source/family/cross-dataset evaluation gate | Complete; no production-quality public-dataset scores are claimed until users supply reviewed files |
| Risk fusion | Versioned configurable weights/thresholds and boundary tests | Complete |
| Drift | Tested bounded mean-shift detector and database table/API | **Incomplete:** runtime monitoring of required signals, persisted drift events, metrics and candidate gating |
| Analyst feedback | Immutable original result, eligibility gate, audit entry | Complete; retraining-candidate query/export remains |
| Incidents | Deterministic source/time grouping | **Incomplete:** destination/signature/reason/stage/escalation grouping evidence and incident timeline/detail controls |
| Explanation layer | Deterministic template and allow-list sanitizer | **Incomplete:** OpenAI-compatible/local providers, timeout/retry/rate limit/cache/fallback, API/UI and AI label |
| Database/retention | All minimum tables, indexes, UUID idempotency, cleanup and backup docs | **Incomplete:** scheduled cleanup command, sanitized/IP-anonymized export and health-event writes |
| API | Required endpoint paths, auth, CORS, pagination bounds, REST/WebSocket tests | **Incomplete:** date/protocol/host flow filters, structured global errors, exports and richer incident/system responses |
| Dashboard | Seven navigation views, live alerts, feedback, responsive states | **Incomplete:** all brief-listed overview analytics, alert pause/filters/ack, incident detail, exports, host/model/system depth |
| Security | Threat model, bounded inputs, local ports, non-root/read-only containers, CI scans | **Incomplete:** HTTP/body/WebSocket limits, structured redacted logging and explicit queue backpressure counters |
| Observability | Detection/alert/latency/WebSocket/database/model/queue metrics | **Incomplete:** remaining required sensor/signature/processing/drift counters and structured JSON service logs |
| Resilience | Durable acknowledgement, retries, pending recovery, real Compose restart matrix, previous-valid model fallback | Complete |
| Automated tests | 50 Python tests plus Vitest/Playwright, Redis/PostgreSQL recovery, migration, model-fallback and Compose fault injection | **Incomplete:** expanded property, UI and performance coverage remains |
| Demo and commands | Required Make targets, offline Compose demo and cleanup | Complete |
| CI/CD | Python/frontend/Compose/integration/migration/audit/Trivy/gitleaks jobs | Complete; final remote run must be verified after publication |
| Documentation | Required topic files and screenshots exist | **Incomplete:** refresh after remaining implementation and remove outdated completion claims |
| GitHub publication | Public `sting-raider/AegisFlow` repository and `main` default branch | Complete; final remote run still tracked under CI/CD |

The project is not complete while any row is marked incomplete. `docs/PROGRESS.md` must
remain consistent with this matrix as work lands.
