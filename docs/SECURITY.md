# Security operations

AegisFlow is single-organization, single-security-domain software. It does not implement
tenant isolation. Do not host mutually untrusted organizations in one deployment or rely
on roles as a tenant boundary.

## Required production controls

- Put the dashboard behind a TLS 1.2+ identity-aware gateway; redirect HTTP and add HSTS
  only after hostname validation.
- Use organizational OIDC or mounted digest-only service keys. Demo authentication is
  forbidden outside demo mode. Apply gateway-wide limits when the API is replicated.
- Keep PostgreSQL, Redis, and API ports private. Use default-deny policies/firewalls and
  allow only the necessary sensor, detector, API, dashboard, identity, and admin paths.
- Run application containers non-root with read-only filesystems, dropped capabilities,
  `no-new-privileges`, resource limits, and default seccomp. Live sensors receive only
  `NET_RAW` on an authorized Linux interface.
- Mount secrets from the orchestrator; never bake or log them. Redact `Authorization`,
  `X-API-Key`, and WebSocket bearer subprotocol headers at every proxy/logging layer.
- Give detectors read-only model access. Treat joblib as executable content; admit only
  independently reviewed, checksum-bound artifacts from the trusted registry.
- Encrypt database/model backups, restrict and audit access, keep copies off-host, and
  rehearse clean restoration.

## Abuse and privacy controls

OIDC validation fixes issuer, audience, algorithm, lifetime, role mapping, and bounded
JWKS refresh. CORS uses exact HTTPS origins; WebSockets require authenticated origin-
checked connections. Bodies, pages, streams, frames, queues, retries, and provider output
are bounded. Malformed/schema-invalid records become visible hash-only errors, never
benign results. Default exports pseudonymize addresses and escape spreadsheet formulas.

Optional explanation providers are disabled by default, receive allow-listed endpoint-
free aggregates, and cannot affect detection or action. Remote providers require HTTPS;
local mode accepts loopback only. Prompt text embedded in alerts is untrusted data.

## Operating procedure

Run `make production-check` before every release and preserve its redacted result. Run
Gitleaks, dependency audits, filesystem/container vulnerability scans, RBAC/JWT/CORS/
WebSocket/export/model-governance abuse tests, artifact replacement tests, and the restore
and rollback drills. Patch base images and dependencies through the controlled
[`UPGRADE.md`](UPGRADE.md) process.

Report suspected credential, artifact, or platform compromise through the organization's
security channel. Preserve sanitized logs and checksums, rotate credentials at their
authority, and follow [`INCIDENT_RESPONSE.md`](INCIDENT_RESPONSE.md). The detailed threat
inventory and residual risks are in [`THREAT_MODEL.md`](THREAT_MODEL.md).
