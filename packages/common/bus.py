from __future__ import annotations

import json
from collections.abc import Iterator
from typing import Any, cast

from redis import Redis
from redis.exceptions import ResponseError


class RedisStreamBus:
    def __init__(self, url: str, *, maxlen: int = 100_000) -> None:
        self.redis: Redis = Redis.from_url(url, decode_responses=True)
        self.maxlen = maxlen

    def ping(self) -> bool:
        return bool(self.redis.ping())

    def publish(self, stream: str, payload: dict[str, Any]) -> str:
        return str(
            self.redis.xadd(
                stream,
                {"payload": json.dumps(payload, separators=(",", ":"))},
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
        response = cast(
            list[tuple[str, list[tuple[str, dict[str, str]]]]],
            self.redis.xreadgroup(group, consumer, {stream: ">"}, count=count, block=block_ms),
        )
        for _, messages in response:
            for message_id, fields in messages:
                yield str(message_id), json.loads(fields["payload"])

    def acknowledge(self, stream: str, group: str, message_id: str) -> None:
        self.redis.xack(stream, group, message_id)
