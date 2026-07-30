from packages.contracts import DetectionResult, FlowEvent, SignatureEvent


def test_contract_schemas_have_stable_versions_and_required_fields() -> None:
    flow = FlowEvent.model_json_schema()
    detection = DetectionResult.model_json_schema()
    signature = SignatureEvent.model_json_schema()
    assert "bytes_forward" in flow["required"]
    assert "feature_schema_version" in detection["properties"]
    assert "raw_event_hash" in signature["properties"]
