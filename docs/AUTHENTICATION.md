# Authentication and authorization

AegisFlow has three explicit authentication modes. `demo` is the default only when
`AEGISFLOW_DEMO=1`; startup refuses that combination when demo mode is disabled.
Non-demo deployments use either signed OIDC access tokens or hashed static API keys.

## Roles

Roles are hierarchical: `admin` includes `analyst` and `viewer`, and `analyst` includes
`viewer`.

| Capability | Viewer | Analyst | Admin |
|---|---:|---:|---:|
| Read alerts, incidents, flows, hosts, models, health depth | yes | yes | yes |
| Use alert/system WebSockets and anonymized exports | yes | yes | yes |
| Acknowledge, add notes, change incident status, submit feedback | no | yes | yes |
| Request explanations and inspect/export retraining candidates | no | yes | yes |
| Export raw endpoint identifiers | no | no | yes |
| Read the durable audit ledger | no | no | yes |
| Register or promote a model candidate; request rollback | no | no | yes |

The server derives the audit actor from the authenticated subject. Mutation bodies do
not accept an `actor` field, so a client cannot attribute an action to another user.
Candidate creators cannot review their own candidate, and a promoter needs an approval
from a different authenticated identity.

## OIDC resource-server mode

Set:

```text
AEGISFLOW_DEMO=0
AEGISFLOW_AUTH_MODE=oidc
AEGISFLOW_OIDC_ISSUER=https://identity.example.com/
AEGISFLOW_OIDC_AUDIENCE=aegisflow-api
AEGISFLOW_OIDC_JWKS_URL=https://identity.example.com/.well-known/jwks.json
AEGISFLOW_OIDC_ALGORITHMS=RS256
AEGISFLOW_OIDC_ROLES_CLAIM=roles
AEGISFLOW_OIDC_ROLE_MAP={"soc-viewers":"viewer","soc-analysts":"analyst","soc-admins":"admin"}
```

JWT verification requires a trusted asymmetric algorithm, matching issuer and audience,
`sub`, `iat`, and `exp`, a bounded lifetime, and a recognized JWKS `kid`. JWKS responses
are HTTPS-only except for loopback testing, size/key-count bounded, redirect-disabled,
and cached for a bounded interval. Unknown key IDs and provider failures share a bounded
refresh backoff so unauthenticated tokens cannot amplify outbound JWKS traffic. Role
mapping is an explicit allow-list; an
authenticated token with no mapped role cannot read the API.

## Optional local Dex acceptance profile

`compose.oidc.yml` exercises the resource-server contract against a real local Dex IdP;
it is not a production dependency or a substitute for the organization's IdP. The profile
uses HTTPS with a generated seven-day local CA, a pinned Dex image, an ephemeral tmpfs
database, public OAuth clients, and generated viewer/analyst/admin credentials. Plaintext
test credentials and private keys exist only under ignored `.runtime/oidc/`; the tooling
never prints or commits them.

Run the complete acceptance drill with:

```text
make oidc-acceptance OIDC_OUTPUT=docs/acceptance/oidc-local.json
make oidc-stop
```

The drill validates HTTPS discovery and JWKS retrieval, signed token issuance, issuer and
audience binding, server-derived viewer/analyst/admin roles, denied escalation, raw-export
authorization, durable audit attribution, browser-compatible WebSocket authentication,
malformed and wrong-audience token rejection, per-principal rate limiting, signing-key
rotation, expiry, and the configured clock skew. It recreates only the disposable Dex
container during the key-rotation check. A failed check writes a NO-GO report and exits
nonzero. To intentionally rotate the local passwords and certificates before rerunning,
use `uv run --extra dev python -m scripts.prepare_oidc_acceptance --force`.

The password grant exists only to automate this isolated acceptance profile. Production
browser clients must use authorization code with PKCE; do not copy the local static-user
configuration into a real deployment.

The secret-free aggregate from the accepted Linux CI drill is retained at
`docs/acceptance/oidc-ci-2026-08-13.json` (GitHub Actions run `31679100788`). It passed
all 11 checks in 95.08 seconds. This evidence applies only to the disposable local Dex
contract; each target deployment must still validate its organizational provider and
gateway-wide rate limiting.

Send the access token as `Authorization: Bearer <token>`. The dashboard can be placed
behind an identity-aware reverse proxy that injects the verified bearer token into both
HTTP and WebSocket upstream requests. A SPA OIDC client can alternatively call the
dashboard's in-memory `setAccessToken` helper; the token is not persisted by AegisFlow.

WebSockets accept the ordinary `Authorization` header for non-browser clients. Browser
clients may offer `aegisflow` plus `aegisflow.bearer.<JWT>` as WebSocket subprotocols.
Tokens in URL query parameters are not accepted. Configure proxies to redact
`Authorization` and `Sec-WebSocket-Protocol` and never write either header to access
logs.

## Hashed API-key mode

This mode is intended for service accounts, isolated evaluations, and organizations that
cannot yet provide OIDC. `AEGISFLOW_API_KEYS_FILE` points to a mounted secret file; the
file stores only SHA-256 digests of high-entropy keys:

```json
{
  "schema_version": "1.0.0",
  "keys": [
    {
      "id": "soc-automation",
      "subject": "soc-automation@example.com",
      "display_name": "SOC automation",
      "sha256": "replace-with-a-64-character-sha256-digest",
      "roles": ["viewer"]
    }
  ]
}
```

Generate at least 32 random bytes with the organization's secret manager, store the raw
key only there, and place its digest in the mounted file. Clients send the raw key in
`X-API-Key`. A restart is required after rotation; overlapping old/new digests allow a
controlled rollover. Do not put raw keys in `.env`, Compose YAML, images, or Git.

For browser WebSockets, base64url-encode the raw key and offer
`aegisflow.key.<encoded>` only in a tightly controlled non-OIDC evaluation. OIDC or an
identity-aware proxy is preferred for human sessions.

## Rate limits and audit trail

Authenticated principals receive separate bounded per-process read, mutation, and
WebSocket-connection windows. Defaults are 1,200 reads, 120 mutations, and 30 WebSocket
connections per minute. `429` responses include `Retry-After: 60`; Prometheus exposes
authentication, authorization, and rate-limit rejection counters. Multi-replica
deployments must also enforce a shared limit at the API gateway because the application
window is intentionally process-local.

`GET /api/v1/audit-events` is admin-only. It records authenticated acknowledgements,
feedback, incident changes/notes, explanation requests, retraining access, raw exports,
and model-governance transitions without packet payloads or credentials. Operational
retention defaults to 30 days while `AEGISFLOW_AUDIT_RETENTION_DAYS` defaults to 365;
organizations must align that value and encrypted backups with their policy.

`/health/live`, `/health/ready`, the OpenAPI document, and documentation remain public
for orchestrator probes and integration. `/metrics` and every `/api/v1` route require at
least `viewer` outside demo mode. OpenAPI advertises both bearer and API-key schemes; the
configured runtime mode decides which one is accepted.
