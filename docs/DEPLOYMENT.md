# Deployment

The base Compose file is the reproducible single-host demo. It binds only the API and dashboard to loopback; PostgreSQL and Redis remain
inside the Compose network. Backend containers run as UID 10001, drop capabilities,
and use `no-new-privileges`. The demo model bundle is baked into the read-only image
after checksum generation. PostgreSQL and Redis persist to named volumes.
Long-running services use `restart: unless-stopped`. Stream consumers retry Redis with
bounded backoff and reclaim abandoned work after `AEGISFLOW_PENDING_IDLE_MS` (30 seconds
by default). Keep this timeout above normal processing latency in production.

Ingress and queue limits are configurable with `AEGISFLOW_HTTP_MAX_BODY_BYTES`,
`AEGISFLOW_WEBSOCKET_MAX_CONNECTIONS`, `AEGISFLOW_WEBSOCKET_MAX_PAYLOAD_BYTES`,
`AEGISFLOW_STREAM_MAXLEN`, `AEGISFLOW_STREAM_MAX_PAYLOAD_BYTES`, and
`AEGISFLOW_BACKPRESSURE_THRESHOLD`. Detector and database batch bounds are configured by
`AEGISFLOW_DETECTOR_BATCH_SIZE` (64), `AEGISFLOW_DETECTOR_BATCH_WAIT_MS` (250 ms), and
`AEGISFLOW_PERSISTENCE_BATCH_SIZE` (64). Defaults are intentionally conservative for the
single-host demo. Size them from measured traffic and memory, keep reverse-proxy limits
at least as strict, and alert on `queue_capacity_utilization`,
`queue_backpressure_events_total`, and `flows_dropped_total`.

Application, sensor, detector, API access, and API runtime events are emitted as one-line
JSON with timestamp, level, service, event type, correlation/flow/model identifiers, and
error code plus bounded batch counts and duration where applicable. Missing fields are
explicit nulls. Credential patterns, control characters,
and addresses are redacted; malformed queue records are represented only by a SHA-256
and bounded structural summary.

Non-demo startup requires OIDC or a mounted hashed API-key file; demo authentication is
refused when `AEGISFLOW_DEMO=0`. Use exact HTTPS CORS origins, keep identity and database
credentials in an orchestrator secret, and read [`AUTHENTICATION.md`](AUTHENTICATION.md).
Back up PostgreSQL with
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

Retention defaults to 30 operational days and 365 audit days and runs after the first
configured interval. Configure `AEGISFLOW_RETENTION_DAYS`,
`AEGISFLOW_AUDIT_RETENTION_DAYS`, `AEGISFLOW_RETENTION_INTERVAL_SECONDS`, or disable the
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

## Production Compose baseline

`compose.production.yml` is a hardened evaluation baseline, not a capacity claim. It
forces non-demo OIDC configuration, reads the PostgreSQL password and SQLAlchemy URL from
Docker secret files, gives the API a shared writable model volume while detector replicas
mount it read-only, mounts evaluation reports read-only, adds resource/log bounds and
health checks, and defaults to two detector replicas. The base API/dashboard ports remain
loopback-only for a host TLS proxy.

Create two uncommitted files with restrictive permissions: one containing only the raw
PostgreSQL password and one containing the complete SQLAlchemy URL. Then set:

```text
AEGISFLOW_DB_PASSWORD_SECRET_FILE=/secure/path/postgres-password
AEGISFLOW_DATABASE_URL_SECRET_FILE=/secure/path/database-url
AEGISFLOW_OIDC_ISSUER=https://identity.example.com/
AEGISFLOW_OIDC_AUDIENCE=aegisflow-api
AEGISFLOW_OIDC_JWKS_URL=https://identity.example.com/.well-known/jwks.json
AEGISFLOW_CORS_ORIGINS=https://aegisflow.example.com
AEGISFLOW_EVALUATION_REPORT_HOST_DIR=/srv/aegisflow/evaluations
```

Render first, then start without the demo profile:

```bash
docker compose -f compose.yml -f compose.production.yml config --quiet
docker compose -f compose.yml -f compose.production.yml up -d --build
docker compose -f compose.yml -f compose.production.yml ps
```

Keep `AEGISFLOW_MODEL_GOVERNANCE_ENABLED=0` until the shared registry and report directory
are populated, access-controlled, backed up, and rollback-tested. Enabling it authorizes
only authenticated admin requests; it does not bypass evaluation or independent review.
Promotion returns `restart_required=true`. Restart API/detectors in a controlled rollout
and confirm every replica reports the promoted version before considering it active.

Use a TLS 1.2+ reverse proxy or identity-aware gateway in front of the loopback dashboard.
Redirect HTTP to HTTPS, enable HSTS after hostname validation, forward WebSocket upgrade
headers, preserve the exact `Host`, enforce request and connection limits at least as
strict as AegisFlow, and redact `Authorization`, `X-API-Key`, and
`Sec-WebSocket-Protocol`. Do not expose PostgreSQL, Redis, or the API port publicly. A
multi-replica API needs a gateway-wide rate limit because application rate windows are
per process.

## Kubernetes baseline

`infra/kubernetes` is a Kustomize baseline for an organizational cluster. It contains
non-root/read-only API, detector and dashboard deployments, migration init, health
probes, resource bounds, disruption budgets, TLS ingress, ingress NetworkPolicies, and
RWX claims for versioned models/evidence. PostgreSQL advisory locking serializes Alembic
when multiple pod init containers start together. Replicated APIs do not run competing
retention threads; a daily `Forbid`-concurrency CronJob owns cleanup and system status
reports that external policy. The baseline intentionally omits stateful databases and all
secrets. Use managed PostgreSQL/Redis, create `aegisflow-runtime-secrets` out of band,
replace every `example.invalid` value and image tag, adapt the ingress-controller
namespace, and render before applying:

```bash
kubectl kustomize infra/kubernetes > rendered-aegisflow.yaml
kubectl apply --server-side --dry-run=server -f rendered-aegisflow.yaml
```

Do not apply the checked-in placeholders. Validate storage access modes, database/Redis
latency, queue capacity, WebSocket behavior, backup/restore, and rolling restart behavior
in the target cluster. The manifest does not establish those properties by existing.

## Release and rollback sequence

1. Freeze the candidate configuration and evaluation reports; run lint, strict types,
   tests, dashboard build/E2E, migrations, Compose/Kustomize rendering, scans, and the
   representative benchmark appropriate to the target.
2. Build immutable backend/dashboard image digests, generate an SBOM with the
   organization's tooling, scan/sign them, and record the Git commit and image digests.
3. Back up PostgreSQL and the model/evaluation registry and complete a restore rehearsal.
4. Apply migrations once, roll API instances, then detector instances. Stop if readiness,
   queue lag, database errors, authentication failures, or model versions diverge.
5. Smoke PCAP replay only against the isolated deployment; never replay at an external
   system. Confirm exact event conservation and zero unacknowledged backlog.
6. To reverse an application release, redeploy the previous immutable image digest. To
   reverse a model, use the audited admin rollback endpoint and restart workers. Database
   downgrades are not automatic; prefer forward fixes unless a separately tested restore
   plan authorizes recovery.

No hosted-cluster rollout has been executed by this repository. Each organization must
retain its render, scan, backup/restore, load, and rollout evidence before approval.

Detector replicas share one Redis consumer group and receive disjoint pending entries.
Container hostnames make the default consumer names unique; deterministic detection IDs
and database constraints make recovery idempotent. Scale only after measuring the
database boundary and keeping `AEGISFLOW_PENDING_IDLE_MS` above worst-case batch latency:

```bash
docker compose -f compose.yml -f compose.demo.yml up -d --scale detector=2 detector
```

The recorded two-replica smoke exercised both workers and drained both queues, but did
not establish linear scaling because PostgreSQL persistence remained dominant. See
[`PERFORMANCE.md`](PERFORMANCE.md).
