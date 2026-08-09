# Threat model

| Threat | Controls | Residual risk |
|---|---|---|
| Malicious PCAP | Extension/size/packet limits, parser isolation, schema validation | Native parser bugs; sandbox high-risk uploads |
| Malformed EVE | 1 MiB line cap, strict JSON/field validation, dead letter | Log flooding |
| Queue flooding | Stream/message byte caps, bounded reads, consumer groups, capacity utilization and transition counters, explicit drop metric | Sustained overload can still exhaust the configured retention window |
| SQL injection | SQLAlchemy parameters, typed filters, bounded pages | Administrator-written raw SQL |
| Identity/token abuse | Demo auth refused outside demo mode; OIDC signature/issuer/audience/lifetime checks; explicit role mapping; hashed static keys; server-derived actor; RBAC; per-principal limits | IdP compromise, stolen bearer token, process-local limits across replicas |
| WebSocket abuse | Viewer authentication, origin allow-list, no query tokens, bounded connection/rate/frame limits, rejection metrics | Bearer subprotocol headers must be redacted by proxies; connection state is process-local |
| Model tampering | Required manifest/SHA-256/schema/order; report-to-bundle binding; independent review/promotion identities; atomic pointer/history; read-only detector mount | Trusted registry/control-plane compromise; joblib is executable |
| Path traversal | Fixed registry layout, resolved PCAP path, extension/size checks | Host-side symlink policy |
| Baseline poisoning | Suspicious data excluded; only analyst-approved benign candidates; public gates can reject but never auto-promote; creator/reviewer/promoter separation | Colluding or compromised privileged accounts |
| Prompt injection | Recursive field allow-list; endpoint-free aggregates; untrusted JSON boundary; embedded instructions ignored; bounded output; deterministic fallback; output cannot reach detection/action code | A provider can still produce misleading advisory prose, which is visibly labelled |
| Credential leakage | Mounted DB/API-key secrets, hashed static-key metadata, HTTPS JWKS, log redaction, hash-only dead letters | Misconfigured orchestration, ingress, or third-party runtime logs |
| Excess retention | No payload, separate operational/audit retention, default export anonymization | Operational endpoint metadata and authorized analyst notes |
| Container escape | Non-root, read-only, cap drop, no-new-privileges | Runtime/kernel vulnerability |
| Detector DoS | 64 KiB HTTP bodies, bounded WebSocket frames/connections, 1 MiB stream messages, backpressure counters, batch caps, hash-only dead letters | Adversarial valid feature load |

No active response is enabled. Detection availability cannot authorize blocking.
