# API

OpenAPI is available at `/docs`. The versioned base is `/api/v1`.

Read endpoints cover alerts, incidents, flows, hosts, model versions, drift, and
system status. Mutations record alert feedback and incident status. List endpoints
bound `limit` to 200. `X-Correlation-ID` is echoed or generated. If
`AEGISFLOW_API_KEY` is set, mutations require `X-API-Key`.

WebSockets:

- `/api/v1/stream/alerts`
- `/api/v1/stream/system`

Clients reconnect with bounded delay. Safe CORS defaults allow only local dashboard
origins. Production deployments must configure explicit origins and an API key or
place the API behind organizational authentication.
