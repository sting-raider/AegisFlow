# Threat model

| Threat | Controls | Residual risk |
|---|---|---|
| Malicious PCAP | Extension/size/packet limits, parser isolation, schema validation | Native parser bugs; sandbox high-risk uploads |
| Malformed EVE | 1 MiB line cap, strict JSON/field validation, dead letter | Log flooding |
| Queue flooding | Stream max length, bounded reads, consumer groups, lag metrics | Sustained overload drops/evicts |
| SQL injection | SQLAlchemy parameters, typed filters, bounded pages | Administrator-written raw SQL |
| WebSocket abuse | Loopback default, proxy auth/rate limits, connection metric | Directly exposed dev API |
| Model tampering | Required manifest, SHA-256, exact schema/order, immutable demo image/read-only production mount | Trusted registry or image compromise; joblib is executable |
| Path traversal | Fixed registry layout, resolved PCAP path, extension/size checks | Host-side symlink policy |
| Baseline poisoning | Suspicious data excluded; only analyst-approved benign candidates | Compromised analyst account |
| Prompt injection | Recursive field allow-list; endpoint-free aggregates; untrusted JSON boundary; embedded instructions ignored; bounded output; deterministic fallback; output cannot reach detection/action code | A provider can still produce misleading advisory prose, which is visibly labelled |
| Credential leakage | Environment/mounted secrets, redacted structured logging | Misconfigured orchestration |
| Excess retention | No payload, configurable cleanup, export anonymization policy | Operational endpoint metadata |
| Container escape | Non-root, read-only, cap drop, no-new-privileges | Runtime/kernel vulnerability |
| Detector DoS | Bounded inputs, backpressure, batch caps, dead letter | Adversarial valid feature load |

No active response is enabled. Detection availability cannot authorize blocking.
