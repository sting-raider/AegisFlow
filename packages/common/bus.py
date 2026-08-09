from __future__ import annotations

import hashlib
import json
from collections.abc import Callable, Iterator
from typing import Any, cast

from redis import Redis
from redis.exceptions import ResponseError


class MessageTooLargeError(ValueError):
    pass


class BatchMessageTooLargeError(MessageTooLargeError):
    def __init__(self, index: int) -> None:
        super().__init__(f"stream payload at batch index {index} exceeds configured byte limit")
        self.index = index


_STREAM_ERROR = "_aegisflow_stream_error"
_STREAM_SHA256 = "_aegisflow_stream_sha256"
_STREAM_BYTES = "_aegisflow_stream_bytes"
_STREAM_ERROR_CODES = frozenset({"JSONDecodeError", "KeyError", "TypeError", "UnicodeError"})


def stream_error_code(envelope: dict[str, object], fallback: str) -> str:
    value = envelope.get(_STREAM_ERROR)
    return str(value) if value in _STREAM_ERROR_CODES else fallback


def _decode_stream_fields(fields: dict[str, str]) -> dict[str, Any]:
    raw = fields.get("payload")
    if not isinstance(raw, str):
        raw_bytes = b"" if raw is None else str(raw).encode("utf-8", errors="replace")
        error_code = "KeyError" if raw is None else "TypeError"
        return {
            _STREAM_ERROR: error_code,
            _STREAM_SHA256: hashlib.sha256(raw_bytes).hexdigest(),
            _STREAM_BYTES: len(raw_bytes),
        }
    raw_bytes = raw.encode("utf-8")
    try:
        decoded = json.loads(raw)
        if not isinstance(decoded, dict):
            raise TypeError("stream payload must decode to an object")
        return cast(dict[str, Any], decoded)
    except (json.JSONDecodeError, TypeError, UnicodeError) as exc:
        return {
            _STREAM_ERROR: type(exc).__name__,
            _STREAM_SHA256: hashlib.sha256(raw_bytes).hexdigest(),
            _STREAM_BYTES: len(raw_bytes),
        }


def safe_dead_letter(
    source: str, envelope: dict[str, object], error_code: str
) -> dict[str, object]:
    canonical = json.dumps(envelope, default=str, sort_keys=True, separators=(",", ":"))
    expected_fields = sorted(set(envelope) & {"flow", "signature", "detection"})
    stream_digest = envelope.get(_STREAM_SHA256)
    is_stream_summary = (
        stream_error_code(envelope, "") in _STREAM_ERROR_CODES
        and set(envelope) == {_STREAM_ERROR, _STREAM_SHA256, _STREAM_BYTES}
        and isinstance(stream_digest, str)
        and len(stream_digest) == 64
        and all(character in "0123456789abcdef" for character in stream_digest)
    )
    return {
        "source": source,
        "error_code": error_code,
        "event_sha256": (
            stream_digest
            if is_stream_summary
            else hashlib.sha256(canonical.encode()).hexdigest()
        ),
        "expected_fields_present": expected_fields,
        "unexpected_field_count": len(set(envelope) - set(expected_fields)),
    }


class RedisStreamBus:
    def __init__(
        self,
        url: str,
        *,
        maxlen: int = 100_000,
        max_payload_bytes: int = 1_048_576,
        claim_idle_ms: int = 30_000,
        client: Redis | None = None,
        on_backpressure: Callable[[str], None] | None = None,
    ) -> None:
        self.redis: Redis = client or Redis.from_url(url, decode_responses=True)
        self.maxlen = max(100, maxlen)
        self.max_payload_bytes = max(1024, max_payload_bytes)
        self.claim_idle_ms = claim_idle_ms
        self.on_backpressure = on_backpressure

    def ping(self) -> bool:
        return bool(self.redis.ping())

    def publish(self, stream: str, payload: dict[str, Any]) -> str:
        serialized = json.dumps(payload, separators=(",", ":"))
        if len(serialized.encode()) > self.max_payload_bytes:
            raise MessageTooLargeError("stream payload exceeds configured byte limit")
        stream_length = int(cast(Any, self.redis.xlen(stream)))
        if self.on_backpressure is not None and stream_length >= self.maxlen:
            self.on_backpressure(stream)
        return str(
            self.redis.xadd(
                stream,
                {"payload": serialized},
                maxlen=self.maxlen,
                approximate=True,
            )
        )

    def publish_batch(self, stream: str, payloads: list[dict[str, Any]]) -> list[str]:
        """Atomically append a bounded payload group with one Redis round trip."""
        if not payloads:
            raise ValueError("stream publish batch cannot be empty")
        serialized: list[str] = []
        for index, payload in enumerate(payloads):
            value = json.dumps(payload, separators=(",", ":"))
            if len(value.encode()) > self.max_payload_bytes:
                raise BatchMessageTooLargeError(index)
            serialized.append(value)
        stream_length = int(cast(Any, self.redis.xlen(stream)))
        if self.on_backpressure is not None and stream_length >= self.maxlen:
            self.on_backpressure(stream)
        pipeline = self.redis.pipeline(transaction=True)
        for value in serialized:
            pipeline.xadd(
                stream,
                {"payload": value},
                maxlen=self.maxlen,
                approximate=True,
            )
        results = pipeline.execute()
        if len(results) != len(payloads):
            raise RuntimeError("Redis returned an incomplete stream publish batch")
        return [str(message_id) for message_id in results]

    def ensure_group(self, stream: str, group: str) -> None:
        try:
            self.redis.xgroup_create(stream, group, id="0", mkstream=True)
        except ResponseError as exc:
            if "BUSYGROUP" not in str(exc):
                raise

    def consume(
        self,
        stream: str,
        group: str,
        consumer: str,
        *,
        count: int = 20,
        block_ms: int = 2_000,
    ) -> Iterator[tuple[str, dict[str, Any]]]:
        yield from self.consume_batch(
            stream,
            group,
            consumer,
            count=count,
            block_ms=block_ms,
        )

    def consume_batch(
        self,
        stream: str,
        group: str,
        consumer: str,
        *,
        count: int = 20,
        block_ms: int = 2_000,
    ) -> list[tuple[str, dict[str, Any]]]:
        """Read a bounded batch, reclaiming abandoned work before new entries."""
        if count < 1:
            raise ValueError("stream batch count must be positive")
        self.ensure_group(stream, group)
        messages = list(self.recover_pending(stream, group, consumer, count=count))[:count]
        remaining = count - len(messages)
        if remaining == 0:
            return messages
        response = cast(
            list[tuple[str, list[tuple[str, dict[str, str]]]]],
            self.redis.xreadgroup(
                group,
                consumer,
                {stream: ">"},
                count=remaining,
                block=block_ms,
            ),
        )
        for _, stream_messages in response:
            for message_id, fields in stream_messages[:remaining]:
                messages.append((str(message_id), _decode_stream_fields(fields)))
                remaining -= 1
                if remaining == 0:
                    return messages
        return messages

    def recover_pending(
        self,
        stream: str,
        group: str,
        consumer: str,
        *,
        count: int = 20,
    ) -> Iterator[tuple[str, dict[str, Any]]]:
        """Claim messages abandoned by a stopped consumer after a bounded idle period."""
        response = cast(
            list[Any],
            self.redis.xautoclaim(
                stream,
                group,
                consumer,
                min_idle_time=self.claim_idle_ms,
                start_id="0-0",
                count=count,
            ),
        )
        messages = cast(list[tuple[str, dict[str, str]]], response[1] if len(response) > 1 else [])
        for message_id, fields in messages:
            yield str(message_id), _decode_stream_fields(fields)

    def group_status(self, stream: str, group: str) -> dict[str, int]:
        """Return bounded queue-health fields supported by Redis 7 consumer groups."""
        self.ensure_group(stream, group)
        groups = cast(list[dict[str, Any]], self.redis.xinfo_groups(stream))
        current = next((item for item in groups if item.get("name") == group), None)
        if current is None:
            return {"pending": 0, "lag": 0, "consumers": 0}
        lag = current.get("lag")
        return {
            "pending": max(0, int(current.get("pending", 0))),
            "lag": max(0, int(lag)) if lag is not None else 0,
            "consumers": max(0, int(current.get("consumers", 0))),
        }

    def acknowledge(self, stream: str, group: str, message_id: str) -> None:
        self.redis.xack(stream, group, message_id)

    def acknowledge_many(
        self,
        stream: str,
        group: str,
        message_ids: list[str],
    ) -> None:
        if message_ids:
            self.redis.xack(stream, group, *message_ids)
