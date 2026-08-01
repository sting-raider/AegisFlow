# API

OpenAPI is available at `/docs`. The versioned base is `/api/v1`.

Read endpoints cover alerts, incidents, flows, hosts, model versions, drift, and
system status. Mutations record alert feedback and incident status. List endpoints
bound `limit` to 200. Alerts accept UTC `start`/`end`, severity, verdict, protocol,
and host filters; flows accept UTC `start`/`end`, protocol, and host filters. Naive
timestamps and reversed ranges are rejected. `X-Correlation-ID` is echoed or generated. If
`AEGISFLOW_API_KEY` is set, mutations require `X-API-Key`.

Errors use a stable `error` envelope containing `code`, a safe `message`, and the
correlation ID. Validation errors include field locations and error types without
echoing request values. Unexpected exceptions return a redacted `internal_error`.

Operational exports are bounded to 200 rows:

- `GET /api/v1/exports/flows.csv`
- `GET /api/v1/exports/alerts.csv`
- `GET /api/v1/exports/retraining-candidates.csv`

Flow and alert exports pseudonymize addresses by default with an ephemeral per-export
HMAC salt; pass `anonymize_ips=false` only for an authorized local workflow. Export
columns are allow-listed and never include protocol metadata, packet contents, or raw
payloads. Retraining candidates contain only analyst-approved `benign_new_behaviour`
rows and the fixed feature registry—never addresses, comments, or analyst identities.
CSV formula prefixes are escaped. When `AEGISFLOW_API_KEY` is configured, disabling
address anonymization requires the matching `X-API-Key` header.

`POST /api/v1/alerts/{alert_id}/acknowledge` records the first acknowledgement in the
audit log. Repeated acknowledgements are idempotent.

System status includes `queue.pending`, `queue.lag`, and `queue.consumers` for the
detection-to-API consumer group. Prometheus exposes the same work state as `queue_pending`
and `queue_lag`. It also reports bounded recent health events and effective retention
configuration.

WebSockets:

- `/api/v1/stream/alerts`
- `/api/v1/stream/system`

Clients reconnect with bounded delay. Safe CORS defaults allow only local dashboard
origins. Production deployments must configure explicit origins and an API key or
place the API behind organizational authentication.

Incident list responses include derived alert counts, endpoint sets, reason/signature
sets, attack stages, escalation count, maximum risk, acknowledgement summary, and a
chronological timeline. `GET /api/v1/incidents/{incident_id}` additionally returns the
full related alerts. `POST /api/v1/incidents/{incident_id}/status` accepts only `open`,
`investigating`, `contained`, or `closed` and advances the incident version.

Incident explanations are fetched on demand from
`GET /api/v1/incidents/{incident_id}/explanation`. The response identifies the requested
and actual provider, whether text is AI-generated, deterministic fallback, or cached,
the incident-version hash, generation time, and limitations. This endpoint uses only
sanitized aggregate evidence and is not part of ingestion or detection. See
[`AI_EXPLANATIONS.md`](AI_EXPLANATIONS.md).
