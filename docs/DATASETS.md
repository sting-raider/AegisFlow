# Dataset and evaluation policy

Full datasets are never committed. The authoritative source catalog is
`configs/datasets/catalog.json`; it identifies the official landing pages and expected
layouts for CIC-IDS2017, CSE-CIC-IDS2018, UNSW-NB15, user-provided NFStream CSV, and
the bundled synthetic smoke generator. Do not replace an official file with a mirror
without recording that decision and a new fingerprint.

Official pages:

- CIC-IDS2017: <https://www.unb.ca/cic/datasets/ids-2017.html>
- CSE-CIC-IDS2018: <https://www.unb.ca/cic/datasets/ids-2018.html>
- UNSW-NB15: <https://research.unsw.edu.au/projects/unsw-nb15-dataset>

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
UNSW-NB15 fields without an equivalent (packet-length/IAT dispersion and TCP flag
counts) are set to zero and recorded as adapter notes; these approximations must be
considered when interpreting cross-dataset drift. Raw IPs, flow IDs, and other
identifiers are profiled for leakage but excluded from the feature array and report.

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
```

Time, capture-day, source-file-grouped, leave-one-family-out, and compatible
cross-dataset paths are implemented. Preprocessing is fit only on the training fold.
The JSON report contains input fingerprints, label normalization/class distributions,
duplicates, constants, missing/infinite counts, identifier and predictive-column
leakage checks, train/test overlap, cross-dataset feature drift, per-class and aggregate
metrics, PR/ROC AUC when defined, calibration, benign false-positive rate, unknown
detection, false alerts per replay hour when timestamps span time, latency, throughput,
and process resource deltas. Offline reports explicitly mark Redis queue lag as not
measured; runtime benchmarking covers that separate scope.
