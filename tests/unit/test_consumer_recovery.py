from unittest.mock import Mock

from sqlalchemy.exc import SQLAlchemyError

from apps.api.consumer import DetectionConsumer
from apps.api.database import Repository
from packages.common.bus import RedisStreamBus
from packages.detection import DetectionEngine
from packages.model_bundle import ModelBundle
from services.sensor import DemoAdapter


def detection_envelope(bundle: ModelBundle) -> dict[str, object]:
    flow = next(iter(DemoAdapter().flows()))
    detection = DetectionEngine(bundle).detect(flow)
    return {
        "flow": flow.model_dump(mode="json"),
        "detection": detection.model_dump(mode="json"),
        "signature": None,
    }


def test_database_failure_is_retried_before_acknowledgement(bundle: ModelBundle) -> None:
    repository = Mock(spec=Repository)
    repository.ingest.side_effect = [SQLAlchemyError("offline"), None]
    bus = Mock(spec=RedisStreamBus)
    database_error = Mock()
    consumer = DetectionConsumer(
        repository,
        "redis://unused",
        bus=bus,
        retry_base_seconds=0,
        on_database_error=database_error,
    )

    assert consumer.process_message("1-0", detection_envelope(bundle))
    assert repository.ingest.call_count == 2
    database_error.assert_called_once_with()
    bus.acknowledge.assert_called_once_with("aegisflow:detections", "api-core", "1-0")


def test_exhausted_database_retry_remains_pending(bundle: ModelBundle) -> None:
    repository = Mock(spec=Repository)
    repository.ingest.side_effect = SQLAlchemyError("offline")
    bus = Mock(spec=RedisStreamBus)
    consumer = DetectionConsumer(
        repository,
        "redis://unused",
        bus=bus,
        database_attempts=2,
        retry_base_seconds=0,
    )

    assert not consumer.process_message("2-0", detection_envelope(bundle))
    assert repository.ingest.call_count == 2
    bus.acknowledge.assert_not_called()


def test_schema_error_is_quarantined_and_acknowledged() -> None:
    repository = Mock(spec=Repository)
    bus = Mock(spec=RedisStreamBus)
    consumer = DetectionConsumer(repository, "redis://unused", bus=bus)
    envelope = {"flow": {"schema_version": "unsupported"}}

    assert consumer.process_message("3-0", envelope)
    repository.ingest.assert_not_called()
    bus.publish.assert_called_once()
    assert bus.publish.call_args.args[0] == "aegisflow:dead-letter"
    bus.acknowledge.assert_called_once_with("aegisflow:detections", "api-core", "3-0")
