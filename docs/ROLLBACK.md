# Rollback

Rollback is a controlled recovery operation, not an automatic detector action. Stop when
the exact prior application/model/database compatibility is unknown.

## Application rollback

1. Record the failed release digest, first failure time, readiness, error, queue, and
   conservation state.
2. Stop further rollout. Keep Redis and PostgreSQL available unless their integrity is in
   question so pending work can remain recoverable.
3. Redeploy the previous immutable API image digest, wait for readiness, then redeploy the
   previous detector digest. Roll the dashboard independently when only UI behavior failed.
4. Confirm every replica uses the intended application and model versions.
5. Run the isolated synthetic replay and require exact counts plus zero final queue lag.

Do not downgrade the database automatically. If the previous application cannot use the
upgraded schema, choose a tested forward fix or invoke the separately approved database-
restore plan. Preserve forensic state before destructive recovery.

## Model rollback

Use the authenticated admin rollback endpoint; it validates checksum history and writes
an audit event. Restart API and detectors, then confirm the returned `restart_required`
condition is resolved on every replica. A corrupt or incompatible history entry is not a
fallback: leave detection failed visibly.

## Validation and closure

Measure API interruption, detection interruption, backlog recovery time, event loss,
duplicate IDs, final pending/lag, and any alert delay. Target zero silent data loss and
zero duplicate durable rows. Record why rollback was chosen, exact digests/checksums,
operator identities, database migration state, evidence retained, and the corrective-
action owner.
