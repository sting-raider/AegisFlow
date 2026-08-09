from __future__ import annotations

import json
import logging
import math
import re
from datetime import UTC, datetime
from typing import Any, Literal

_IP_ADDRESS = re.compile(r"(?<![\w:])(?:\d{1,3}\.){3}\d{1,3}(?![\w:])")
_SECRET = re.compile(
    r"(?i)(authorization|api[_-]?key|password|secret|token)(\s*[:=]\s*)([^\s,;]+)"
)
_CONTROL = re.compile(r"[\x00-\x1f\x7f]+")


def redact_log_text(value: object, *, limit: int = 512) -> str:
    text = _CONTROL.sub(" ", str(value))
    text = _SECRET.sub(r"\1\2[redacted]", text)
    text = _IP_ADDRESS.sub("[ip-redacted]", text)
    return " ".join(text.split())[:limit]


class JsonLogFormatter(logging.Formatter):
    def __init__(self, service: str) -> None:
        super().__init__()
        self.service = service

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "timestamp": datetime.now(UTC).isoformat(),
            "level": record.levelname.lower(),
            "service": self.service,
            "event_type": redact_log_text(getattr(record, "event_type", record.getMessage())),
            "correlation_id": _optional(record, "correlation_id"),
            "flow_id": _optional(record, "flow_id"),
            "model_version": _optional(record, "model_version"),
            "error_code": _optional(record, "error_code"),
            "batch_size": _optional_number(record, "batch_size"),
            "published_count": _optional_number(record, "published_count"),
            "rejected_count": _optional_number(record, "rejected_count"),
            "duration_ms": _optional_number(record, "duration_ms"),
        }
        return json.dumps(payload, separators=(",", ":"), sort_keys=True)


class _JsonStreamHandler(logging.StreamHandler[Any]):
    pass


def _optional(record: logging.LogRecord, name: str) -> str | None:
    value = getattr(record, name, None)
    return redact_log_text(value, limit=128) if value is not None else None


def _optional_number(record: logging.LogRecord, name: str) -> int | float | None:
    value = getattr(record, name, None)
    if isinstance(value, bool) or not isinstance(value, int | float):
        return None
    return value if math.isfinite(value) else None


def service_logger(service: str) -> logging.Logger:
    return configure_json_logger(f"aegisflow.{service}", service)


def configure_json_logger(
    name: str, service: str, *, replace_handlers: bool = False
) -> logging.Logger:
    logger = logging.getLogger(name)
    if replace_handlers:
        logger.handlers.clear()
    if not any(isinstance(handler, _JsonStreamHandler) for handler in logger.handlers):
        handler = _JsonStreamHandler()
        handler.setFormatter(JsonLogFormatter(service))
        logger.addHandler(handler)
    logger.setLevel(logging.INFO)
    logger.propagate = False
    return logger


def log_event(
    logger: logging.Logger,
    event_type: str,
    *,
    level: Literal["info", "warning", "error"] = "info",
    correlation_id: str | None = None,
    flow_id: str | None = None,
    model_version: str | None = None,
    error_code: str | None = None,
    batch_size: int | None = None,
    published_count: int | None = None,
    rejected_count: int | None = None,
    duration_ms: float | None = None,
) -> None:
    logger.log(
        {"info": logging.INFO, "warning": logging.WARNING, "error": logging.ERROR}[level],
        event_type,
        extra={
            "event_type": event_type,
            "correlation_id": correlation_id,
            "flow_id": flow_id,
            "model_version": model_version,
            "error_code": error_code,
            "batch_size": batch_size,
            "published_count": published_count,
            "rejected_count": rejected_count,
            "duration_ms": duration_ms,
        },
    )
