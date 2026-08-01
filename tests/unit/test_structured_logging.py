from __future__ import annotations

import json
import logging

from packages.common.logging import JsonLogFormatter, log_event, redact_log_text


class RecordingHandler(logging.Handler):
    def __init__(self) -> None:
        super().__init__()
        self.messages: list[str] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.messages.append(self.format(record))


def test_json_log_has_required_shape_without_addresses_or_secrets() -> None:
    logger = logging.getLogger("aegisflow-test-structured")
    logger.handlers.clear()
    logger.propagate = False
    handler = RecordingHandler()
    handler.setFormatter(JsonLogFormatter("test-service"))
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)

    log_event(
        logger,
        "flow_processing_error 192.0.2.10 api_key=do-not-log",
        level="error",
        correlation_id="request-1",
        flow_id="flow-1",
        model_version="0.2.0",
        error_code="schema_invalid",
    )

    payload = json.loads(handler.messages[0])
    assert set(payload) == {
        "timestamp",
        "level",
        "service",
        "event_type",
        "correlation_id",
        "flow_id",
        "model_version",
        "error_code",
    }
    assert payload["level"] == "error"
    assert payload["service"] == "test-service"
    assert "192.0.2.10" not in handler.messages[0]
    assert "do-not-log" not in handler.messages[0]


def test_log_text_strips_control_characters() -> None:
    assert redact_log_text("line\r\npassword: visible") == "line password: [redacted]"
