# Deployment

Compose binds only the API and dashboard to loopback; PostgreSQL and Redis remain
inside the Compose network. Backend containers run as UID 10001, drop capabilities,
and use `no-new-privileges`. The demo model bundle is baked into the read-only image
after checksum generation. PostgreSQL and Redis persist to named volumes.
Long-running services use `restart: unless-stopped`. Stream consumers retry Redis with
bounded backoff and reclaim abandoned work after `AEGISFLOW_PENDING_IDLE_MS` (30 seconds
by default). Keep this timeout above normal processing latency in production.

Set a strong `AEGISFLOW_DB_PASSWORD`, API key, explicit CORS origins, retention, backup
target, and trusted registry or image-promotion permissions before non-demo use.
Place TLS and organizational authentication at the reverse proxy. Back up PostgreSQL with
`pg_dump -Fc` and restore into a clean compatible database with `pg_restore`.

AI explanations remain disabled unless `AEGISFLOW_EXPLANATION_PROVIDER` is explicitly
set. Keep provider keys in an orchestrator secret, never an image or committed `.env`,
and use a reviewed explicit model ID. Remote provider URLs require HTTPS. Local provider
mode accepts loopback only, so it is intended for an API process and compatible model
server on the same host. See [`AI_EXPLANATIONS.md`](AI_EXPLANATIONS.md) for all bounds
and fallback behavior.

Validate configuration:

```bash
docker compose -f compose.yml -f compose.demo.yml config
```
