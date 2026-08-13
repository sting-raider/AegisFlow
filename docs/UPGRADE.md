# Upgrade

Use immutable application image digests and an explicit maintenance window. Never combine
an untested application, database, identity, and model change in one rollout.

## Before the window

1. Review release notes, dependency/security scans, configuration changes, migrations,
   feature schema, model checksum, and known limitations.
2. Run the complete CI gates, `make production-check`, the target-environment capacity
   test, and controlled failure tests against the exact candidate.
3. Create and verify PostgreSQL plus model/evaluation-registry backups. Complete an
   isolated restore rehearsal and record its checksum and timings.
4. Render Compose/Kustomize, confirm secret references and TLS/OIDC endpoints, and verify
   every image reference is an immutable registry digest.
5. Define stop thresholds for readiness, database errors, auth failures, queue lag,
   latency, drops, model divergence, and resource pressure.

## Rollout order

1. Pause scheduled retention and model governance writes if the plan requires it.
2. Apply forward-compatible migrations once. Concurrent Kubernetes init containers are
   advisory-lock serialized, but the operator still owns the migration decision.
3. Roll API replicas one at a time; verify readiness, authentication, and read-only API
   smoke after each batch.
4. Roll detector replicas; confirm the same model version/checksum on every replica and
   watch pending/lag recovery.
5. Roll the dashboard, then replay only the isolated synthetic fixture.
6. Require exact flow/detection conservation, expected deterministic counts, zero final
   pending/lag, and no new processing errors before resuming normal schedules.

## Database compatibility

Alembic upgrades are forward operations. Do not assume an application rollback can safely
downgrade the database. Prefer an additive/expand-contract migration sequence. A database
restore is authorized only by the tested recovery plan and may discard post-backup data;
record that decision explicitly.

Keep the previous image digests and compatible model pointer available until the
observation window closes. Follow [`ROLLBACK.md`](ROLLBACK.md) when a stop threshold is
crossed.
