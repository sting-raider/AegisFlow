# API

OpenAPI is available at `/docs`. The versioned base is `/api/v1`.

Read endpoints cover alerts, incidents, flows, hosts, model versions, drift, and
system status. Mutations record alert feedback and incident status. List endpoints
bound `limit` to 200. Alerts accept UTC `start`/`end`, severity, verdict, protocol,
and host filters; flows accept UTC `start`/`end`, protocol, and host filters. Naive
timestamps and reversed ranges are rejected. `X-Correlation-ID` is echoed or generated.
All `/api/v1` endpoints and `/metrics` require an authenticated viewer outside demo mode.
OIDC bearer tokens and hashed role-bearing API keys are supported; role-specific mutation
rules and configuration are documented in
[`AUTHENTICATION.md`](AUTHENTICATION.md). `GET /api/v1/auth/me` returns the server-derived
subject, display name, role set, and authentication method.

Errors use a stable `error` envelope containing `code`, a safe `message`, and the
correlation ID. Validation errors include field locations and error types without
echoing request values. Unexpected exceptions return a redacted `internal_error`.
Mutation bodies default to a 64 KiB cap. Correlation IDs accept only bounded letters,
digits, dot, underscore, and hyphen; invalid values are replaced instead of reflected.

Operational exports are bounded to 200 rows:

- `GET /api/v1/exports/flows.csv`
- `GET /api/v1/exports/alerts.csv`
- `GET /api/v1/exports/retraining-candidates.csv`

Flow and alert exports pseudonymize addresses by default with an ephemeral per-export
HMAC salt; pass `anonymize_ips=false` only for an authorized local workflow. Export
columns are allow-listed and never include protocol metadata, packet contents, or raw
payloads. Retraining candidates contain only analyst-approved `benign_new_behaviour`
rows and the fixed feature registry—never addresses, comments, or analyst identities.
CSV formula prefixes are escaped. Disabling address anonymization requires `admin`; the
raw export creates a durable audit event containing only actor, action, target, and row
count.

`POST /api/v1/alerts/{alert_id}/acknowledge` records the first acknowledgement in the
audit log. Repeated acknowledgements are idempotent.

System status includes `queue.pending`, `queue.lag`, `queue.consumers`, capacity,
utilization, backpressure state/transition count, current throughput, explicit drops,
worker latency, signature-event count, and Suricata observation state for the
detection-to-API consumer group. Prometheus exposes the same work state as `queue_pending`
and `queue_lag`, plus every required flow/signature/detection/latency/drift/error metric.
It also reports bounded recent health events and effective retention configuration.

WebSockets:

- `/api/v1/stream/alerts`
- `/api/v1/stream/system`

Clients reconnect with bounded delay. Safe CORS defaults allow only local dashboard
origins. Production deployments must configure their exact HTTPS dashboard origin and
OIDC identity boundary. WebSockets enforce the same origin allow-list and viewer role,
default to 32 concurrent connections, and cap outbound frames at 256 KiB. Browser bearer
tokens use a WebSocket subprotocol rather than a query parameter. An oversized frame becomes a visible
`processing_error`; it is never silently presented as an empty benign result.

Incident list responses include derived alert counts, endpoint sets, reason/signature
sets, attack stages, escalation count, maximum risk, acknowledgement summary, and a
chronological timeline. `GET /api/v1/incidents/{incident_id}` additionally returns the
full related alerts. `POST /api/v1/incidents/{incident_id}/status` accepts only `open`,
`investigating`, `contained`, or `closed` and advances the incident version.
`POST /api/v1/incidents/{incident_id}/notes` records a bounded analyst note as an audit
event and advances the incident version; incident detail returns the chronological note
ledger. Notes never enter detection, explanation prompts, or retraining candidates.
Acknowledgements, feedback, notes, and status changes ignore client attribution because
the authenticated subject is the sole audit actor.

Incident explanations are fetched on demand from
`GET /api/v1/incidents/{incident_id}/explanation`. The response identifies the requested
and actual provider, whether text is AI-generated, deterministic fallback, or cached,
the incident-version hash, generation time, and limitations. This endpoint uses only
sanitized aggregate evidence and is not part of ingestion or detection. See
[`AI_EXPLANATIONS.md`](AI_EXPLANATIONS.md).

Model-governance endpoints are:

- `GET /api/v1/model-candidates` and `GET /api/v1/model-candidates/{id}` (`viewer`)
- `POST /api/v1/model-candidates/{model_name}` (`admin` registration)
- `POST /api/v1/model-candidates/{id}/reviews` (`analyst` review)
- `POST /api/v1/model-candidates/{id}/promote` (`admin`, explicitly enabled)
- `POST /api/v1/models/{model_name}/rollback` (`admin`, explicitly enabled)

Registration revalidates the exact bundle and sanitized report files. A failing report
or missing required mode makes the candidate durably `rejected`; it cannot be reviewed
or promoted. Promotion rechecks every checksum after review, atomically updates the
pointer, and reports `restart_required=true`. It never hot-swaps an in-flight detector.
`GET /api/v1/audit-events` is admin-only and supports bounded actor/action filters.
