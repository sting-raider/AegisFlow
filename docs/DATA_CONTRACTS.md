# Data contracts

`packages/contracts/models.py` owns version `1.0.0` Pydantic contracts.

- `FlowEvent` is a completed, bidirectional, payload-free flow with UTC timestamps,
  endpoint metadata, packet/byte/IAT statistics, bounded first-packet summaries,
  adapter identity, extractor version, and a standard Community ID v1 correlation key.
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

Community ID follows the
[Corelight Community ID specification](https://github.com/corelight/community-id-spec).
It is an unordered interoperability identifier, not a security hash and not evidence of
traffic direction. A native Suricata `flow_id` is never relabelled as Community ID.
