from __future__ import annotations

import argparse
import hashlib
import json
import lzma
import os
import tempfile
import urllib.parse
import urllib.request
from datetime import UTC, datetime
from pathlib import Path

MAX_FILE_BYTES = 8 * 1024 * 1024 * 1024

OFFICIAL_BASE = "https://mcfp.felk.cvut.cz/publicDatasets"

SOURCES: dict[str, dict[str, str]] = {
    "CTU-IoT-Malware-Capture-34-1": {
        "role": "malware_environment",
        "family": "Linux.Mirai",
        "url": f"{OFFICIAL_BASE}/IoT-23-Dataset/IndividualScenarios/"
        "CTU-IoT-Malware-Capture-34-1/2018-12-21-15-50-14-192.168.1.195.pcap",
        "labels": f"{OFFICIAL_BASE}/IoT-23-Dataset/IndividualScenarios/"
        "CTU-IoT-Malware-Capture-34-1/bro/conn.log.labeled",
    },
    "CTU-IoT-Malware-Capture-8-1": {
        "role": "malware_environment",
        "family": "Linux.Hakai",
        "url": f"{OFFICIAL_BASE}/IoT-23-Dataset/IndividualScenarios/"
        "CTU-IoT-Malware-Capture-8-1/2018-07-31-15-15-09-192.168.100.113.pcap",
        "labels": f"{OFFICIAL_BASE}/IoT-23-Dataset/IndividualScenarios/"
        "CTU-IoT-Malware-Capture-8-1/bro/conn.log.labeled",
    },
    "CTU-IoT-Malware-Capture-42-1": {
        "role": "malware_environment",
        "family": "Linux.Torii",
        "url": f"{OFFICIAL_BASE}/IoT-23-Dataset/IndividualScenarios/"
        "CTU-IoT-Malware-Capture-42-1/2019-01-10-14-34-38-192.168.1.197.pcap",
        "labels": f"{OFFICIAL_BASE}/IoT-23-Dataset/IndividualScenarios/"
        "CTU-IoT-Malware-Capture-42-1/bro/conn.log.labeled",
    },
    "CTU-IoT-Malware-Capture-20-1": {
        "role": "malware_environment",
        "family": "Linux.Mirai",
        "url": f"{OFFICIAL_BASE}/IoT-23-Dataset/IndividualScenarios/"
        "CTU-IoT-Malware-Capture-20-1/2018-10-02-13-12-30-192.168.100.103.pcap",
        "labels": f"{OFFICIAL_BASE}/IoT-23-Dataset/IndividualScenarios/"
        "CTU-IoT-Malware-Capture-20-1/bro/conn.log.labeled",
    },
    "CTU-Honeypot-Capture-4-1": {
        "role": "benign_environment",
        "family": "honeypot_devices",
        "url": f"{OFFICIAL_BASE}/IoT-23-Dataset/IndividualScenarios/"
        "CTU-Honeypot-Capture-4-1/2018-10-25-14-06-32-192.168.1.132.pcap.xz",
        "labels": f"{OFFICIAL_BASE}/IoT-23-Dataset/IndividualScenarios/"
        "CTU-Honeypot-Capture-4-1/bro/conn.log.labeled",
    },
    "CTU-Honeypot-Capture-5-1": {
        "role": "benign_environment",
        "family": "honeypot_devices",
        "url": f"{OFFICIAL_BASE}/IoT-23-Dataset/IndividualScenarios/"
        "CTU-Honeypot-Capture-5-1/2018-09-21-capture.pcap",
        "labels": f"{OFFICIAL_BASE}/IoT-23-Dataset/IndividualScenarios/"
        "CTU-Honeypot-Capture-5-1/bro/conn.log.labeled",
    },
    "CTU-IoT-Malware-Capture-35-1": {
        "role": "benign_environment",
        "family": "real_device_benign",
        "url": f"{OFFICIAL_BASE}/IoT-23-Dataset/IndividualScenarios/"
        "CTU-IoT-Malware-Capture-35-1/2018-12-21-15-33-59-192.168.1.196.pcap",
        "labels": f"{OFFICIAL_BASE}/IoT-23-Dataset/IndividualScenarios/"
        "CTU-IoT-Malware-Capture-35-1/bro/conn.log.labeled",
    },
    "CTU-IoT-Malware-Capture-43-1": {
        "role": "reserved_final_or_benign_environment",
        "family": "real_device_benign",
        "url": f"{OFFICIAL_BASE}/IoT-23-Dataset/IndividualScenarios/"
        "CTU-IoT-Malware-Capture-43-1/2019-01-10-19-22-51-192.168.1.198.pcap",
        "labels": f"{OFFICIAL_BASE}/IoT-23-Dataset/IndividualScenarios/"
        "CTU-IoT-Malware-Capture-43-1/bro/conn.log.labeled",
    },
}


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def fetch(url: str, destination: Path, *, max_bytes: int = MAX_FILE_BYTES) -> None:
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme != "https" or parsed.hostname != "mcfp.felk.cvut.cz":
        raise ValueError("v2 acquisition accepts only the official Stratosphere host")
    destination.parent.mkdir(parents=True, exist_ok=True)
    partial = destination.with_suffix(f"{destination.suffix}.part")
    offset = partial.stat().st_size if partial.exists() else 0
    request = urllib.request.Request(
        url, headers={"Range": f"bytes={offset}-"} if offset else {}
    )
    with urllib.request.urlopen(request, timeout=120) as response:
        status = getattr(response, "status", 200)
        if offset and status != 206:
            offset = 0
        mode = "ab" if offset and status == 206 else "wb"
        downloaded = offset if mode == "ab" else 0
        with partial.open(mode) as output:
            while chunk := response.read(1024 * 1024):
                downloaded += len(chunk)
                if downloaded > max_bytes:
                    raise RuntimeError(f"{destination.name} exceeds the {max_bytes} byte limit")
                output.write(chunk)
    partial.replace(destination)


def decompress_xz(source: Path) -> Path:
    target = source.with_suffix("")
    if target.exists():
        return target
    temporary = target.with_suffix(target.suffix + ".part")
    with lzma.open(source, "rb") as reader, temporary.open("wb") as writer:
        while chunk := reader.read(1024 * 1024):
            writer.write(chunk)
    temporary.replace(target)
    return target


def acquire(
    scenario: str, directory: Path, *, pinned: dict[str, object] | None
) -> dict[str, object]:
    spec = SOURCES[scenario]
    raw_name = Path(urllib.parse.urlparse(spec["url"]).path).name
    raw_path = directory / raw_name
    expected = (pinned or {}).get("raw_sha256")
    if raw_path.exists():
        actual = sha256_file(raw_path)
        if isinstance(expected, str) and actual != expected:
            raise RuntimeError(f"checksum mismatch for {raw_path.name}: {actual} != {expected}")
    else:
        print(f"downloading {scenario}: {spec['url']}", flush=True)
        fetch(spec["url"], raw_path)
    if raw_path.suffix == ".xz":
        pcap_path = decompress_xz(raw_path)
    else:
        pcap_path = raw_path
    labels_name = Path(urllib.parse.urlparse(spec["labels"]).path).name
    labels_path = directory / f"{scenario}.{labels_name}"
    if not labels_path.exists():
        print(f"downloading labels for {scenario}", flush=True)
        fetch(spec["labels"], labels_path)
    record: dict[str, object] = {
        "scenario": scenario,
        "role": spec["role"],
        "family": spec["family"],
        "official_base": OFFICIAL_BASE,
        "pcap_url": spec["url"],
        "labels_url": spec["labels"],
        "pcap_filename": pcap_path.name,
        "labels_filename": labels_path.name,
        "pcap_size_bytes": pcap_path.stat().st_size,
        "pcap_sha256": sha256_file(pcap_path),
        "labels_sha256": sha256_file(labels_path),
        "retrieved_at": datetime.now(UTC).isoformat(),
    }
    descriptor, temporary_name = tempfile.mkstemp(prefix=".v2-manifest-", dir=directory)
    with os.fdopen(descriptor, "w", encoding="utf-8") as output:
        json.dump(record, output, indent=2, sort_keys=True)
        output.write("\n")
    os.replace(temporary_name, directory / f"{scenario}.manifest.json")
    return record


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Acquire official IoT-23 scenario PCAPs for Detector-v2 development"
    )
    parser.add_argument("--output", type=Path, default=Path("data/pcap_v2"))
    parser.add_argument("--pinned", type=Path, default=Path("configs/research-v2/pool-hashes.json"))
    parser.add_argument("--only", nargs="*", help="restrict to named scenarios")
    args = parser.parse_args()
    pinned: dict[str, dict[str, object]] = {}
    if args.pinned.exists():
        loaded = json.loads(args.pinned.read_text(encoding="utf-8"))
        if isinstance(loaded, dict):
            pinned = {k: v for k, v in loaded.items() if isinstance(k, str) and isinstance(v, dict)}
    selected = args.only or list(SOURCES)
    unknown = [name for name in selected if name not in SOURCES]
    if unknown:
        raise SystemExit(f"unknown scenarios: {unknown}")
    records = []
    for scenario in selected:
        records.append(
            acquire(scenario, args.output, pinned=pinned.get(scenario))
        )
        print(f"acquired {scenario}", flush=True)
    summary_path = args.output / "acquisition-summary.json"
    summary_path.write_text(json.dumps(records, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"scenarios": [record["scenario"] for record in records]}, indent=2))


if __name__ == "__main__":
    main()
