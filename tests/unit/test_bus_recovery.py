from typing import cast
from unittest.mock import Mock

import pytest
from redis import Redis

from packages.common.bus import MessageTooLargeError, RedisStreamBus, safe_dead_letter


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


def test_publish_rejects_oversized_payload_and_reports_capacity_pressure() -> None:
    redis = Mock()
    redis.xlen.return_value = 100
    redis.xadd.return_value = "1-0"
    pressure = Mock()
    bus = RedisStreamBus(
        "redis://unused",
        client=cast(Redis, redis),
        maxlen=100,
        max_payload_bytes=1024,
        on_backpressure=pressure,
    )

    assert bus.publish("events", {"kind": "small"}) == "1-0"
    pressure.assert_called_once_with("events")
    with pytest.raises(MessageTooLargeError):
        bus.publish("events", {"value": "x" * 2000})


def test_dead_letter_is_hash_only_and_does_not_copy_untrusted_event() -> None:
    dead = safe_dead_letter(
        "events",
        {"flow": {"src_ip": "192.0.2.10", "payload": "secret"}, "token": "hidden"},
        "schema_invalid",
    )

    assert dead["error_code"] == "schema_invalid"
    assert dead["expected_fields_present"] == ["flow"]
    assert dead["unexpected_field_count"] == 1
    assert len(str(dead["event_sha256"])) == 64
    assert "192.0.2.10" not in str(dead)
    assert "secret" not in str(dead)
