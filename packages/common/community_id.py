from __future__ import annotations

import base64
import hashlib
import struct
from ipaddress import IPv4Address, IPv6Address, ip_address

IPAddress = IPv4Address | IPv6Address
FlowKey = tuple[str, int, str, int, int]

_PROTOCOL_NUMBERS = {
    "ICMP": 1,
    "TCP": 6,
    "UDP": 17,
    "ICMPV6": 58,
    "SCTP": 132,
}
_PORT_PROTOCOLS = {1, 6, 17, 58, 132}
_ICMP_COUNTERPARTS = {
    1: {0: 8, 8: 0, 9: 10, 10: 9, 13: 14, 14: 13, 15: 16, 16: 15, 17: 18, 18: 17},
    58: {
        128: 129,
        129: 128,
        130: 131,
        131: 130,
        133: 134,
        134: 133,
        135: 136,
        136: 135,
        139: 140,
        140: 139,
        144: 145,
        145: 144,
    },
}


def protocol_number(protocol: str | int) -> int:
    if isinstance(protocol, int):
        value = protocol
    else:
        normalized = protocol.strip().upper().replace("_", "")
        known = _PROTOCOL_NUMBERS.get(normalized)
        if known is not None:
            value = known
        else:
            try:
                value = int(normalized)
            except ValueError as exc:
                raise ValueError(f"unsupported IP protocol: {protocol}") from exc
    if not 0 <= value <= 255:
        raise ValueError("IP protocol number must be in [0, 255]")
    return value


def canonical_flow_key(
    src_ip: str | IPAddress,
    src_port: int,
    dst_ip: str | IPAddress,
    dst_port: int,
    protocol: str | int,
) -> FlowKey:
    source = ip_address(src_ip)
    destination = ip_address(dst_ip)
    _validate_endpoints(source, src_port, destination, dst_port)
    first = (source.packed, src_port, source, src_port)
    second = (destination.packed, dst_port, destination, dst_port)
    if (first[0], first[1]) > (second[0], second[1]):
        first, second = second, first
    return str(first[2]), first[3], str(second[2]), second[3], protocol_number(protocol)


def icmp_port_equivalents(protocol: int, message_type: int, code: int) -> tuple[int, int, bool]:
    if protocol not in {1, 58}:
        raise ValueError("ICMP port mapping requires protocol 1 or 58")
    _validate_port(message_type)
    _validate_port(code)
    counterpart = _ICMP_COUNTERPARTS[protocol].get(message_type)
    if counterpart is None:
        return message_type, code, True
    return message_type, counterpart, False


def community_id_v1(
    src_ip: str | IPAddress,
    src_port: int | None,
    dst_ip: str | IPAddress,
    dst_port: int | None,
    protocol: str | int,
    *,
    seed: int = 0,
    one_way: bool = False,
) -> str:
    """Return a standard Community ID v1 string.

    ICMP callers must first map type/code with :func:`icmp_port_equivalents`.
    SHA-1 is required by the interoperability standard and is not used for security.
    """

    if not 0 <= seed <= 65_535:
        raise ValueError("Community ID seed must be in [0, 65535]")
    source = ip_address(src_ip)
    destination = ip_address(dst_ip)
    proto = protocol_number(protocol)
    effective_source_port = 0 if src_port is None else src_port
    effective_destination_port = 0 if dst_port is None else dst_port
    _validate_endpoints(
        source,
        effective_source_port,
        destination,
        effective_destination_port,
    )

    if not one_way and (source.packed, effective_source_port) > (
        destination.packed,
        effective_destination_port,
    ):
        source, destination = destination, source
        effective_source_port, effective_destination_port = (
            effective_destination_port,
            effective_source_port,
        )

    material = (
        struct.pack("!H", seed) + source.packed + destination.packed + struct.pack("!BB", proto, 0)
    )
    if proto in _PORT_PROTOCOLS:
        if src_port is None or dst_port is None:
            raise ValueError("transport and ICMP Community IDs require both port equivalents")
        material += struct.pack("!HH", effective_source_port, effective_destination_port)
    if len(material) % 4:
        raise AssertionError("Community ID material must align to a 32-bit boundary")
    digest = hashlib.sha1(material, usedforsecurity=False).digest()
    return "1:" + base64.b64encode(digest).decode("ascii")


def is_community_id_v1(value: object) -> bool:
    if not isinstance(value, str) or not value.startswith("1:"):
        return False
    try:
        digest = base64.b64decode(value[2:], validate=True)
    except ValueError:
        return False
    return len(digest) == 20


def _validate_endpoints(
    source: IPAddress,
    source_port: int,
    destination: IPAddress,
    destination_port: int,
) -> None:
    if source.version != destination.version:
        raise ValueError("Community ID endpoints must use the same IP version")
    _validate_port(source_port)
    _validate_port(destination_port)


def _validate_port(port: int) -> None:
    if not 0 <= port <= 65_535:
        raise ValueError("port must be in [0, 65535]")
