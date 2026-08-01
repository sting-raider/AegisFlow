# API

OpenAPI is available at `/docs`. The versioned base is `/api/v1`.

Read endpoints cover alerts, incidents, flows, hosts, model versions, drift, and
system status. Mutations record alert feedback and incident status. List endpoints
bound `limit` to 200. `X-Correlation-ID` is echoed or generated. If
`AEGISFLOW_API_KEY` is set, mutations require `X-API-Key`.

System status includes `queue.pending`, `queue.lag`, and `queue.consumers` for the
detection-to-API consumer group. Prometheus exposes the same work state as `queue_pending`
and `queue_lag`.

WebSockets:

- `/api/v1/stream/alerts`
- `/api/v1/stream/system`

Clients reconnect with bounded delay. Safe CORS defaults allow only local dashboard
origins. Production deployments must configure explicit origins and an API key or
place the API behind organizational authentication.

Incident explanations are fetched on demand from
`GET /api/v1/incidents/{incident_id}/explanation`. The response identifies the requested
and actual provider, whether text is AI-generated, deterministic fallback, or cached,
the incident-version hash, generation time, and limitations. This endpoint uses only
sanitized aggregate evidence and is not part of ingestion or detection. See
[`AI_EXPLANATIONS.md`](AI_EXPLANATIONS.md).
