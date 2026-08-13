# Backup and restore

This runbook is for operators of an AegisFlow PostgreSQL deployment. Database backups may
contain sensitive network metadata even though AegisFlow does not store packet payloads.
Encrypt backups, restrict access, keep them off the application host, and never commit a
dump or credential to this repository.

## Define the policy first

Record an owner, encrypted destination, schedule, retention period, expected RPO/RTO,
PostgreSQL compatibility policy, restore-test frequency, and escalation contact. Point
`AEGISFLOW_BACKUP_POLICY_FILE` at the uncommitted attestation described in
[`CONFIGURATION.md`](CONFIGURATION.md). That file documents ownership; it does not create
a backup.

## Create a custom-format backup

For the local Compose profile, write the dump on an access-controlled host filesystem:

```bash
docker compose -f compose.yml -f compose.demo.yml exec -T postgres \
  pg_dump -U aegisflow -d aegisflow -Fc --no-owner --no-acl > aegisflow.dump
sha256sum aegisflow.dump > aegisflow.dump.sha256
```

Do not log the database URL or password. Copy the dump and checksum to the approved
encrypted destination, verify the copy, and apply the documented retention policy.

For managed PostgreSQL, use the provider's point-in-time or snapshot facility when it is
the approved system of record. Still rehearse restoration into an isolated target; a
successful backup job is not restore evidence.

## Restore into a clean target

Never test against the active database. Use an empty compatible PostgreSQL instance with
network access limited to the restore operator and the isolated AegisFlow application.

```bash
sha256sum --check aegisflow.dump.sha256
createdb -h "$RESTORE_DB_HOST" -U "$RESTORE_DB_ADMIN" aegisflow_restore_test
pg_restore -h "$RESTORE_DB_HOST" -U "$RESTORE_DB_ADMIN" \
  -d aegisflow_restore_test --no-owner --no-acl --exit-on-error aegisflow.dump
AEGISFLOW_DATABASE_URL="postgresql+psycopg://.../aegisflow_restore_test" \
  uv run alembic upgrade head
```

Supply credentials through the deployment secret mechanism rather than shell history in
real operations. The URL above is deliberately incomplete.

## Validate before declaring success

Confirm all of the following and retain an aggregate report without row data:

1. The backup checksum matches and `pg_restore` exits zero.
2. `alembic current` reports the repository's expected migration head.
3. Counts and primary-identity digests match the source snapshot for every table.
4. The API readiness endpoint reports both application and database ready.
5. Read-only list calls return the expected flow, alert, and incident totals.
6. Model registry, analyst feedback, audit history, incident membership, and health rows
   are present.
7. The restore target and any temporary dump are removed under the approved cleanup
   process.

`make restore-acceptance` automates these checks against a disposable local Compose
project. See [`RESTORE_DRILL.md`](RESTORE_DRILL.md) for its passed evidence and limits.

## Recovery decision

During a real incident, stop writers or establish the provider-consistent recovery point,
record the chosen backup and its checksum, restore into a new database, validate it, then
switch application secrets during a controlled maintenance window. Do not overwrite the
damaged database until the incident owner preserves required forensic evidence. Roll back
the switch if readiness, migration state, identity digests, or smoke counts fail.
