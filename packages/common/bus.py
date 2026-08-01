from __future__ import annotations

import hashlib
import json
from collections.abc import Callable, Iterator
from typing import Any, cast

from redis import Redis
from redis.exceptions import ResponseError


class MessageTooLargeError(ValueError):
    pass


def safe_dead_letter(
    source: str, envelope: dict[str, object], error_code: str
) -> dict[str, object]:
    canonical = json.dumps(envelope, default=str, sort_keys=True, separators=(",", ":"))
    expected_fields = sorted(set(envelope) & {"flow", "signature", "detection"})
    return {
        "source": source,
        "error_code": error_code,
        "event_sha256": hashlib.sha256(canonical.encode()).hexdigest(),
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
        self.ensure_group(stream, group)
        yield from self.recover_pending(stream, group, consumer, count=count)
        response = cast(
            list[tuple[str, list[tuple[str, dict[str, str]]]]],
            self.redis.xreadgroup(group, consumer, {stream: ">"}, count=count, block=block_ms),
        )
        for _, messages in response:
            for message_id, fields in messages:
                yield str(message_id), json.loads(fields["payload"])

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
            yield str(message_id), json.loads(fields["payload"])

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
