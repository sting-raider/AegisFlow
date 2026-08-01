from typing import cast
from unittest.mock import Mock

from redis import Redis

from packages.common.bus import RedisStreamBus


def test_consume_claims_abandoned_messages_before_reading_new_entries() -> None:
    redis = Mock()
    redis.xautoclaim.return_value = [
        "0-0",
        [("1-0", {"payload": '{"kind":"recovered"}'})],
        [],
    ]
    redis.xreadgroup.return_value = [("events", [("2-0", {"payload": '{"kind":"new"}'})])]
    bus = RedisStreamBus(
        "redis://unused",
        client=cast(Redis, redis),
        claim_idle_ms=1_234,
    )

    messages = list(bus.consume("events", "workers", "worker-2", block_ms=0))

    assert messages == [
        ("1-0", {"kind": "recovered"}),
        ("2-0", {"kind": "new"}),
    ]
    redis.xautoclaim.assert_called_once_with(
        "events",
        "workers",
        "worker-2",
        min_idle_time=1_234,
        start_id="0-0",
        count=20,
    )


def test_group_status_reports_pending_lag_and_consumers() -> None:
    redis = Mock()
    redis.xinfo_groups.return_value = [{"name": "workers", "pending": 3, "lag": 7, "consumers": 2}]
    bus = RedisStreamBus("redis://unused", client=cast(Redis, redis))

    assert bus.group_status("events", "workers") == {
        "pending": 3,
        "lag": 7,
        "consumers": 2,
    }
