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
`pg_dump -Fc` and restore into a clean compatible database with `pg_restore`. For the
Compose deployment, create a host-side custom-format backup with:

```bash
docker compose -f compose.yml -f compose.demo.yml exec -T postgres \
  pg_dump -U aegisflow -d aegisflow -Fc > aegisflow.dump
```

Test restores away from the active database. After creating an empty compatible target,
restore and fail on SQL errors:

```bash
docker compose -f compose.yml -f compose.demo.yml exec -T postgres \
  createdb -U aegisflow aegisflow_restore_test
docker compose -f compose.yml -f compose.demo.yml exec -T postgres \
  pg_restore -U aegisflow -d aegisflow_restore_test --exit-on-error < aegisflow.dump
```

Protect the backup as sensitive operational data, encrypt it at rest, restrict access,
test restoration regularly, and delete the restore-test database after verification.
Never add database dumps to Git.

Retention defaults to 30 days and runs after the first configured interval. Configure
`AEGISFLOW_RETENTION_DAYS`, `AEGISFLOW_RETENTION_INTERVAL_SECONDS`, or disable the
in-process schedule with `AEGISFLOW_RETENTION_ENABLED=0` when an external scheduler owns
cleanup. `make retention-cleanup` performs one immediate cleanup using the same policy
and writes a visible system-health result. Retention does not create or export packet
payloads.

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
