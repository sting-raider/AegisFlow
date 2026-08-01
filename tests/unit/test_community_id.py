from __future__ import annotations

import pytest

from packages.common import (
    canonical_flow_key,
    community_id_v1,
    icmp_port_equivalents,
    is_community_id_v1,
)


@pytest.mark.parametrize(
    ("source", "source_port", "destination", "destination_port", "protocol", "expected"),
    [
        (
            "128.232.110.120",
            34855,
            "66.35.250.204",
            80,
            6,
            "1:LQU9qZlK+B5F3KDmev6m5PMibrg=",
        ),
        (
            "192.168.1.52",
            54585,
            "8.8.8.8",
            53,
            17,
            "1:d/FP5EW3wiY1vCndhwleRRKHowQ=",
        ),
        (
            "2001:470:e5bf:dead:4957:2174:e82c:4887",
            63943,
            "2607:f8b0:400c:c03::1a",
            25,
            6,
            "1:/qFaeAR+gFe1KYjMzVDsMv+wgU4=",
        ),
    ],
)
def test_community_id_matches_corelight_reference_vectors(
    source: str,
    source_port: int,
    destination: str,
    destination_port: int,
    protocol: int,
    expected: str,
) -> None:
    forward = community_id_v1(source, source_port, destination, destination_port, protocol)
    reverse = community_id_v1(destination, destination_port, source, source_port, protocol)
    assert forward == reverse == expected
    assert is_community_id_v1(forward)


def test_canonical_identity_is_unordered_without_changing_semantic_endpoints() -> None:
    forward = canonical_flow_key("203.0.113.9", 55_000, "10.0.0.5", 443, "TCP")
    reverse = canonical_flow_key("10.0.0.5", 443, "203.0.113.9", 55_000, "TCP")
    assert forward == reverse == ("10.0.0.5", 443, "203.0.113.9", 55_000, 6)


def test_icmpv6_counterparts_match_corelight_reference_vector() -> None:
    source_ports = icmp_port_equivalents(58, 128, 0)
    response_ports = icmp_port_equivalents(58, 129, 0)
    assert source_ports == (128, 129, False)
    assert response_ports == (129, 128, False)
    request = community_id_v1(
        "3ffe:507:0:1:200:86ff:fe05:80da",
        source_ports[0],
        "3ffe:501:0:1001::2",
        source_ports[1],
        58,
        one_way=source_ports[2],
    )
    response = community_id_v1(
        "3ffe:501:0:1001::2",
        response_ports[0],
        "3ffe:507:0:1:200:86ff:fe05:80da",
        response_ports[1],
        58,
        one_way=response_ports[2],
    )
    assert request == response == "1:+TW+HtLHvV1xnGhV1lv7XoJrqQg="


def test_community_id_rejects_mixed_ip_versions_and_invalid_renderings() -> None:
    with pytest.raises(ValueError, match="same IP version"):
        community_id_v1("192.0.2.1", 1, "2001:db8::1", 2, "TCP")
    assert not is_community_id_v1("1:fixture")
    assert not is_community_id_v1("tuple:private")
