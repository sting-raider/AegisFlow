# Detector-v2 development source expansion

Review date: 2026-09-10. This review governs development acquisition only. It does not
authorize frozen-final access, model promotion, packet transmission, payload retention,
or automatic response.

## Selected official objects

The next development intake uses two additional daily processed-flow objects from the
official anonymous CSE-CIC-IDS2018 AWS bucket. They are distinct from the existing
February 28 development object and the frozen March 1 object.

| Capture | Intended coverage | Expected bytes | Official S3 ETag |
|---|---|---:|---|
| `Wednesday-14-02-2018_TrafficForML_CICFlowMeter.csv` | FTP and SSH brute force | 358,223,333 | `46c0f45f8e6fe1edf1f08487448c102f-22` |
| `Wednesday-21-02-2018_TrafficForML_CICFlowMeter.csv` | LOIC-UDP and HOIC DDoS | 328,893,673 | `3a1d6b804ba9f6a3085973c2fa425883-20` |

The multipart ETags are transport metadata, not file hashes. Each complete local object
must receive a reviewed SHA-256, byte-count check, adapter quality report, normalized
label distribution, and source-file group before it enters any registered experiment.
Raw CSVs and generated working data remain under ignored `data/` paths.

Official source: <https://www.unb.ca/cic/datasets/ids-2018.html>. The page describes
the daily attack schedule, CICFlowMeter-V3 processed CSVs, anonymous S3 acquisition, and
the citation/link condition for redistribution. The source-object URLs are under
`https://cse-cic-ids2018.s3.ca-central-1.amazonaws.com/Processed%20Traffic%20Data%20for%20ML%20Algorithms/`.

These files improve family support but do not add an independent collection
environment. Dataset-origin diagnostics, grouped splits, independent benign calibration,
and cross-environment tests therefore remain mandatory.

## Sources not selected

ToN-IoT remains a useful future independent environment, but it is not selected for this
intake. Its official UNSW SharePoint folder returned HTTP 403 without institutional
sign-in during the review. The official project page grants academic use while requiring
author agreement for commercial use. Separately, CTU IoT-23 scenario READMEs state that
Stratosphere authorization is required; expanding those captures without resolving that
statement would weaken the existing provenance record.

CIC-IDS2017 is also deferred. Its official download currently requires a data-request
form that returned a server error during review. No mirror substitution is permitted.

## Admission sequence

1. Acquire the exact official S3 objects to ignored storage and compute SHA-256.
2. Run the existing CSE adapter and quality gate; retain every exclusion as an error
   count rather than coercing it to benign.
3. Commit sanitized provenance and quality evidence only after byte and row checks pass.
4. Register any model comparison before fitting, with frozen evidence still sealed.
