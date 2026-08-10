# Dataset and evaluation policy

Full datasets are never committed. The authoritative source catalog is
`configs/datasets/catalog.json`; it identifies the official landing pages and expected
layouts for CIC-IDS2017, CSE-CIC-IDS2018, UNSW-NB15, HIKARI-2021, user-provided NFStream
CSV, and the bundled synthetic smoke generator. Do not replace an official file with a mirror
without recording that decision and a new fingerprint.

Official pages:

- CIC-IDS2017: <https://www.unb.ca/cic/datasets/ids-2017.html>
- CSE-CIC-IDS2018: <https://www.unb.ca/cic/datasets/ids-2018.html>
- UNSW-NB15: <https://research.unsw.edu.au/projects/unsw-nb15-dataset>
- HIKARI-2021 v1.4.0: <https://zenodo.org/records/6463389>
- IoT-23: <https://www.stratosphereips.org/datasets-iot23> and the official
  <https://mcfp.felk.cvut.cz/publicDatasets/IoT-23-Dataset/> repository

The reviewed development-only sources and their exact checksums, row counts, license
notes, limitations, and quality-report fingerprints are in
`configs/datasets/development-pool-v1.json`. They are deliberately distinct from every
source hash in `configs/evaluation/frozen-evidence-v1.json`. Generate a sanitized quality
report and enforce that boundary with:

```bash
uv run python scripts/prepare_development_dataset.py \
  --dataset hikari2021 \
  --input data/hikari2021/ALLFLOWMETER_HIKARI2021.csv \
  --output docs/development/hikari2021-quality.json
```

HIKARI wire-byte totals are reconstructed from its directional payload and header totals.
Its aggregate CSV does not publish trustworthy row timestamps or protocol, so Schema B is
unavailable and the protocol categories make full Schema A a dataset-origin shortcut.
The February 28 CSE file has timestamps but omits endpoints, so Schema B is also
unavailable. These limitations are visible rather than zero-filled.

The reviewed IoT-23 slice uses six exact `conn.log.labeled` objects: Mirai, Torii,
Trojan, Hakai, Philips HUE, and Amazon Echo scenarios. The adapter supports both the
newer tab-delimited and legacy three-space label suffixes, interprets Unix timestamps,
uses Zeek directional IP-layer byte totals, and preserves every file as a capture group.
All 43,009 retained rows have Schema B evidence. Zeek flows with no observed duration use
zero milliseconds and a documented one-microsecond rate floor; zero-packet flows use a
zero packet-length mean. Endpoint identities are profiled for leakage and used transiently
for bounded temporal state but never enter committed features or reports.

Run the development origin diagnostic with explicit source IDs and paths:

```bash
uv run python scripts/evaluate_dataset_origin.py \
  --source hikari hikari2021 data/hikari2021/ALLFLOWMETER_HIKARI2021.csv \
  --source cse_2018_02_28 cse_cic_ids2018 data/cse_cic_ids2018/Wednesday-28-02-2018_TrafficForML_CICFlowMeter.csv \
  --output docs/development/dataset-origin-diagnostic.json
```

The generic downloader requires HTTPS and a reviewed lowercase SHA-256, supports
resumption, enforces expected and maximum sizes, and writes provenance with retrieval
time, license, source page, filename, checksum, capture boundaries, label mapping, and
transformation history. If an official source does not publish a cryptographic hash,
download it through the official mechanism, calculate and review the SHA-256 locally,
then retain the sidecar manifest. AegisFlow never guesses a checksum.

```bash
uv run python scripts/download_dataset.py \
  --dataset-name cic_ids2017 \
  --source-page https://www.unb.ca/cic/datasets/ids-2017.html \
  --url https://reviewed-official-file.example/dataset.csv \
  --output data/cic_ids2017/day.csv \
  --sha256 <reviewed-lowercase-sha256> \
  --expected-size <reviewed-byte-count> \
  --license "See official CIC-IDS2017 page" \
  --capture-boundaries "source CSV/day" \
  --label-mapping configs/datasets/cic-labels.json \
  --transformation "none; original CSV"
```

`training.data.adapters` converts supported CSV schemas into the exact fixed feature
order used at inference. CIC duration/IAT microseconds are converted to milliseconds.
The official UNSW-NB15 training/testing partitions omit transport ports, so destination
port is set to zero; directional `sload`/`dload` bit rates are converted to bytes per
second and summed. Fields without an equivalent (packet-length/IAT dispersion and TCP
flag counts) are set to zero and recorded as adapter notes. These approximations must be
considered when interpreting results. Raw IPs, flow IDs, and other identifiers are
profiled for leakage but excluded from the feature array and report.

Official CSE-CIC-IDS2018 AWS files concatenate per-machine CSV shards. The adapter removes
only rows whose label cell is the repeated CSV header, then excludes canonical rows with
non-finite or registry-invalid features instead of coercing them. Both reasons and counts
are machine-readable in `quality.excluded_rows`. For the reviewed Thursday file this is
25 repeated headers and 2,919 invalid CICFlowMeter rate rows; the remaining 328,181 rows
are evaluated. The source misspelling `Infilteration` is normalized to `infiltration`.

Run a gate with an explicit non-row-random split:

```bash
uv run python -m training.cli.evaluate_dataset \
  --dataset cic_ids2017 \
  --input data/cic_ids2017/Monday.csv \
  --input data/cic_ids2017/Tuesday.csv \
  --split source_file \
  --output reports/cic2017-source-file.json

uv run python -m training.cli.evaluate_dataset \
  --dataset cic_ids2017 \
  --input data/cic_ids2017/Monday.csv \
  --split leave_family_out \
  --held-out-family dos \
  --output reports/cic2017-held-dos.json

uv run python -m training.cli.evaluate_dataset \
  --dataset unsw_nb15 \
  --input data/unsw_nb15/UNSW_NB15_training-set.csv \
  --cross-dataset unsw_nb15 \
  --cross-input data/unsw_nb15/UNSW_NB15_testing-set.csv \
  --output reports/unsw-nb15-official-split.json
```

Time, capture-day, source-file-grouped, leave-one-family-out, and compatible
cross-dataset paths are implemented. Preprocessing is fit only on the training fold.
The JSON report contains input fingerprints, label normalization/class distributions,
duplicates, constants, missing/infinite counts, identifier and predictive-column
leakage checks, train/test overlap, cross-dataset feature drift, per-class and aggregate
metrics, PR/ROC AUC when defined, calibration, benign false-positive rate, unknown
detection, false alerts per replay hour when timestamps span time, latency, throughput,
and process resource deltas. Offline reports explicitly mark Redis queue lag as not
measured; runtime benchmarking covers that separate scope. The evaluation harness uses
the detector's shared exact-hybrid batch predictor. The reviewed official UNSW result is
committed with held-family, CSE chronological, and true cross-dataset reports under
`docs/evaluation/`; source CSVs and sidecar manifests remain ignored under `data/`.
