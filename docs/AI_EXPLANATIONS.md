# Optional incident explanations

Detection, risk fusion, alerting, and incident grouping never call an AI provider.
`GET /api/v1/incidents/{incident_id}/explanation` performs explanation work only when
an analyst opens it. With the default configuration it returns the deterministic local
template and makes no network request.

## Providers

| `AEGISFLOW_EXPLANATION_PROVIDER` | Behavior |
|---|---|
| `disabled` (default) | Deterministic template only; no model, key, or internet required |
| `openai` | HTTPS OpenAI-compatible `v1/chat/completions` provider |
| `local` | OpenAI-compatible endpoint restricted to `localhost`, `127.0.0.1`, or `::1` |

An enabled provider requires an explicit `AEGISFLOW_EXPLANATION_MODEL`. Remote mode
also requires `AEGISFLOW_EXPLANATION_API_KEY` (or `OPENAI_API_KEY`). The key is used
only in the HTTP authorization header; it is never placed in model evidence or the API
response. Missing or unsafe configuration does not disable deterministic explanations.

Example remote configuration:

```text
AEGISFLOW_EXPLANATION_PROVIDER=openai
AEGISFLOW_EXPLANATION_BASE_URL=https://api.openai.com/v1
AEGISFLOW_EXPLANATION_MODEL=<reviewed-model-id>
AEGISFLOW_EXPLANATION_API_KEY=<secret>
```

Example local configuration when the API and compatible model server run on the same
host:

```text
AEGISFLOW_EXPLANATION_PROVIDER=local
AEGISFLOW_EXPLANATION_BASE_URL=http://127.0.0.1:11434/v1
AEGISFLOW_EXPLANATION_MODEL=<installed-local-model>
```

The model identifier has no changing default. Operators must deliberately select and
evaluate one. A remote provider URL must use HTTPS and cannot contain embedded
credentials, query parameters, or fragments. Local mode fails closed for non-loopback
hosts.

## Privacy and injection boundary

The repository constructs a separate endpoint-free evidence envelope. The allow-list is:

- verdict and severity;
- reason codes;
- bounded aggregate flow features;
- known, anomaly, signature, contextual, and fused scores;
- signature names;
- a bounded timeline containing only timestamp, verdict, severity, and risk.

Packet payloads, PCAPs, source/destination addresses, ports, analyst comments,
credentials, environment variables, and secrets are never included. Nested fields are
independently allow-listed, non-finite values are removed, control characters are
stripped, and address-like strings are redacted. Signature names and reason strings are
treated as untrusted JSON data. The system instruction explicitly refuses instructions
inside those values and prohibits firewall, blocking, exploitation, or executable
commands.

Provider output is advisory text only. It is never parsed by detection or response code,
cannot modify an alert, and cannot trigger blocking, retraining, or model promotion. The
dashboard labels successful provider output `AI generated`; local template output is
labelled `deterministic`. Output containing common firewall or blocking command forms is
rejected and replaced by deterministic fallback text.

## Failure controls

- Timeout defaults to 5 seconds and is bounded to 0.1–30 seconds.
- Transient transport, HTTP 429, and HTTP 5xx failures retry once; the hard cap is two.
- Provider requests default to five per API process per minute.
- Successful output is cached in a bounded in-memory LRU by SHA-256 of incident ID,
  incident update version, and canonical sanitized evidence.
- Rate limiting, invalid configuration, response-schema errors, timeouts, and provider
  failures return the deterministic template with a visible fallback reason.

The cache is intentionally process-local and disappears on restart; it stores only
sanitized evidence-derived text and never credentials.
