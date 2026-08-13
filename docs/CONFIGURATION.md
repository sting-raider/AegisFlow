# Production configuration

Run the production preflight from the release workspace before rendering or starting a
deployment:

```text
make production-check
```

The command exits nonzero and prints only named, actionable error codes. It never prints
secret values. The checked-in smoke model is scientifically rejected, so the repository's
default configuration is intentionally a production NO-GO.

## Required identity and browser boundary

Set all of the following explicitly:

```text
AEGISFLOW_DEMO=0
AEGISFLOW_AUTH_MODE=oidc
AEGISFLOW_OIDC_ISSUER=https://identity.example.com/
AEGISFLOW_OIDC_AUDIENCE=aegisflow-api
AEGISFLOW_OIDC_JWKS_URL=https://identity.example.com/.well-known/jwks.json
AEGISFLOW_CORS_ORIGINS=https://aegisflow.example.com
```

Issuer, JWKS, CORS, and WebSocket origins must use HTTPS and must not contain checked-in
`.invalid` placeholders. Wildcards, embedded credentials, empty audiences, and demo auth
fail the preflight. If the optional remote explanation provider is enabled, its base URL
must also use HTTPS and its API key must be present. Explanations remain optional and
cannot affect detection.

## Database secrets

Create two uncommitted, access-controlled files and provide their host paths:

```text
AEGISFLOW_DB_PASSWORD_SECRET_FILE=/secure/path/postgres-password
AEGISFLOW_DATABASE_URL_SECRET_FILE=/secure/path/database-url
```

The first file contains only the PostgreSQL password. The second contains the full
`postgresql+psycopg://` URL. Empty files and known demo/default passwords fail. The
validator reports only the variable name and error code, never either value.

## Retention and backup ownership

Exactly one retention owner must be declared. A single-API Compose deployment may use:

```text
AEGISFLOW_RETENTION_OWNER=api
AEGISFLOW_RETENTION_ENABLED=1
AEGISFLOW_RETENTION_EXTERNAL=0
```

A replicated deployment with a CronJob or external scheduler uses:

```text
AEGISFLOW_RETENTION_OWNER=external
AEGISFLOW_RETENTION_ENABLED=0
AEGISFLOW_RETENTION_EXTERNAL=1
```

`AEGISFLOW_BACKUP_POLICY_FILE` must point to uncommitted JSON owned by the operator:

```json
{
  "schema_version": "1.0.0",
  "owner": "platform-team",
  "schedule": "0 2 * * *",
  "target": "encrypted-managed-backup",
  "encrypted": true,
  "restore_tested_at": "2026-08-01T00:00:00Z"
}
```

This is an attestation input, not a backup implementation. Update it only after an actual
restore drill; do not commit operational storage locations or credentials.

## Model readiness and approval

The preflight loads and checksum-verifies the exact production pointer, rejects fallback,
revalidates every governed report through the deployed hybrid-evaluation contract, and
requires every configured mode with no blockers:

```text
AEGISFLOW_MODEL_REGISTRY=/release/models/registry
AEGISFLOW_MODEL_NAME=aegisflow-candidate
AEGISFLOW_EVALUATION_REPORT_DIR=/release/evaluation
AEGISFLOW_PRODUCTION_EVALUATION_REPORTS=grouped.json,time.json,source.json,held-family.json,cross-dataset.json
AEGISFLOW_MODEL_APPROVAL_FILE=/release/approval/model-approval.json
```

The uncommitted approval attestation binds the exact checksum manifest and preserves
separation of duties:

```json
{
  "schema_version": "1.0.0",
  "decision": "approved",
  "model_name": "aegisflow-candidate",
  "version": "1.2.3",
  "bundle_digest": "64-lowercase-hex-characters",
  "approved_by": "reviewer-subject",
  "promoted_by": "different-promoter-subject"
}
```

An eligible scientific report is not by itself human approval. The approver and promoter
must be distinct. The runtime governance database remains the authoritative audit ledger;
the file is the release-time attestation exported and protected by the operator.

## Deployment shape

The command renders `compose.yml` plus `compose.production.yml` and rejects public
PostgreSQL/Redis ports, host networking for either datastore, non-loopback application
ports, writable application root filesystems, added application capabilities, missing
`no-new-privileges`, or a missing API healthcheck. Kubernetes deployments must apply the
same controls and undergo their separate cluster acceptance drill.
