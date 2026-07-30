# Data contracts

`packages/contracts/models.py` owns version `1.0.0` Pydantic contracts.

- `FlowEvent` is a completed, bidirectional, payload-free flow with UTC timestamps,
  endpoint metadata, packet/byte/IAT statistics, bounded first-packet summaries,
  adapter identity, and extractor version.
- `SignatureEvent` stores normalized signature fields, a hash of the source event,
  and an allow-listed metadata subset. Raw EVE JSON is not persisted.
- `DetectionResult` records classifier probabilities/confidence, anomaly/open-set,
  signature/context scores, risk, verdict, reason codes, versions, and latency.

Unknown extra fields are ignored for forward compatibility. Missing required fields,
invalid ranges, non-finite values, mismatched IP versions, and incompatible schemas
fail visibly. Generate schemas with:

```bash
uv run python -c "from packages.contracts import FlowEvent; print(FlowEvent.model_json_schema())"
```
