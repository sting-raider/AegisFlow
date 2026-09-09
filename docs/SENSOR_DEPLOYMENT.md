# Sensor deployment

AegisFlow supports deterministic demo traffic, offline PCAP replay, Suricata EVE input,
and explicit local live capture. Prefer offline replay during evaluation. No sensor is
authorized to scan, inject, replay onto, or block an external system.

## PCAP replay

Keep captures outside Git, mount them read-only, and confirm authorization and retention
before processing:

```bash
make replay PCAP=/absolute/path/authorized-capture.pcap
```

The adapter retains flow metadata, never packet payloads. Invalid extensions, oversized
files, malformed packets, schema mismatches, and feature-bound violations fail visibly.

## Suricata integration

Use EVE flow and alert records from a separately governed Suricata deployment. AegisFlow
hashes DNS names and correlates signatures by Community ID and time; it does not store
raw payloads or authorize Suricata blocking. Test the bundled isolated profile with:

```bash
make suricata-replay PCAP=/absolute/path/authorized-capture.pcap
```

The replay container has no network. Review and pin external rules before deployment;
record their source, version, license, checksum, and update owner.

## Live Linux capture

Live capture requires a named, explicitly authorized local interface:

```bash
make live INTERFACE=eth0
```

Use a SPAN/TAP interface where possible. The dedicated sensor image runs non-root with a
read-only root filesystem and only `NET_RAW`; promiscuous mode is disabled. Do not grant
`NET_ADMIN`, host networking, or access to unrelated interfaces for convenience. See
[`LIVE_CAPTURE.md`](LIVE_CAPTURE.md) for the verified Linux loopback probe.

## Experimental Windows capture

NFStream PCAP processing is verified on Windows with Npcap installed at its standard
`C:\Windows\System32\Npcap` location. Native live capture accepts only an explicitly
named local interface and retains the same non-promiscuous, payload-free flow boundary.
It has not completed the isolated live-interface acceptance probe, so do not treat it as
equivalent to the accepted Linux container path. Validate it first on a controlled local
or lab interface; never use it to scan, inject, or replay traffic.

## Commissioning checklist

Record sensor ID, owner, interface/source, authorization, clock synchronization, expected
traffic rate, Redis TLS/network boundary, stream limits, data-retention policy, and a
rollback contact. Start at a measured low rate. Confirm flow direction and Community ID
on controlled fixtures, visible processing errors for malformed input, zero silent drops,
and queue depth/lag below the target envelope before widening coverage.
