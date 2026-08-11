# Development anomaly/open-set baseline results

Experiment: `DEV-ANO-001`

Code commit: `c91aadc678e179d000cc1f549bbff50b703cc99d`

Generated: `2026-08-10T08:43:27.504165+00:00`

This is development-only evidence. One environment supplies benign fit data, a
second supplies benign calibration, and the third is completely held out. No
attack family enters anomaly fit or calibration.

| Model | Complete | Failed | Mean direct unknown recall | Worst direct recall | Mean detection-or-review | Worst detection-or-review | Mean benign FPR | Worst benign FPR |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| isolation_forest | 6 | 0 | 0.00479 | 0.00013 | 0.08101 | 0.00357 | 0.01697 | 0.04659 |
| robust_covariance | 6 | 0 | 0.02878 | 0.00000 | 0.15814 | 0.00000 | 0.04450 | 0.10854 |
| local_outlier_factor | 6 | 0 | 0.04052 | 0.00000 | 0.06733 | 0.00000 | 0.03350 | 0.07058 |
| one_class_svm | 6 | 0 | 0.06281 | 0.00000 | 0.12288 | 0.00000 | 0.07059 | 0.18817 |
| denoising_autoencoder | 6 | 0 | 0.04096 | 0.00000 | 0.10857 | 0.00000 | 0.04243 | 0.17353 |

## Runs

### isolation_forest: fit cse_2018_02_28, calibrate iot23, test hikari

Direct recall `0.00098`; detection-or-review `0.01812`; benign FPR `0.00569`; PR-AUC `0.69649`.

### robust_covariance: fit cse_2018_02_28, calibrate iot23, test hikari

Direct recall `0.00000`; detection-or-review `0.00000`; benign FPR `0.00027`; PR-AUC `0.65144`.

### local_outlier_factor: fit cse_2018_02_28, calibrate iot23, test hikari

Direct recall `0.00000`; detection-or-review `0.00000`; benign FPR `0.00000`; PR-AUC `0.57914`.

### one_class_svm: fit cse_2018_02_28, calibrate iot23, test hikari

Direct recall `0.04427`; detection-or-review `0.16274`; benign FPR `0.05349`; PR-AUC `0.68211`.

### denoising_autoencoder: fit cse_2018_02_28, calibrate iot23, test hikari

Direct recall `0.01465`; detection-or-review `0.03233`; benign FPR `0.01693`; PR-AUC `0.62113`.

### isolation_forest: fit iot23, calibrate cse_2018_02_28, test hikari

Direct recall `0.02072`; detection-or-review `0.29196`; benign FPR `0.04659`; PR-AUC `0.72480`.

### robust_covariance: fit iot23, calibrate cse_2018_02_28, test hikari

Direct recall `0.00000`; detection-or-review `0.00000`; benign FPR `0.00000`; PR-AUC `0.59010`.

### local_outlier_factor: fit iot23, calibrate cse_2018_02_28, test hikari

Direct recall `0.00000`; detection-or-review `0.00000`; benign FPR `0.00135`; PR-AUC `0.39768`.

### one_class_svm: fit iot23, calibrate cse_2018_02_28, test hikari

Direct recall `0.00000`; detection-or-review `0.00000`; benign FPR `0.00582`; PR-AUC `0.45236`.

### denoising_autoencoder: fit iot23, calibrate cse_2018_02_28, test hikari

Direct recall `0.00000`; detection-or-review `0.00000`; benign FPR `0.00000`; PR-AUC `0.43244`.

### isolation_forest: fit hikari, calibrate iot23, test cse_2018_02_28

Direct recall `0.00013`; detection-or-review `0.15452`; benign FPR `0.00040`; PR-AUC `0.49369`.

### robust_covariance: fit hikari, calibrate iot23, test cse_2018_02_28

Direct recall `0.08564`; detection-or-review `0.09428`; benign FPR `0.10854`; PR-AUC `0.48336`.

### local_outlier_factor: fit hikari, calibrate iot23, test cse_2018_02_28

Direct recall `0.07912`; detection-or-review `0.07912`; benign FPR `0.06539`; PR-AUC `0.49519`.

### one_class_svm: fit hikari, calibrate iot23, test cse_2018_02_28

Direct recall `0.17606`; detection-or-review `0.20266`; benign FPR `0.18817`; PR-AUC `0.49830`.

### denoising_autoencoder: fit hikari, calibrate iot23, test cse_2018_02_28

Direct recall `0.06888`; detection-or-review `0.32593`; benign FPR `0.06099`; PR-AUC `0.49607`.

### isolation_forest: fit iot23, calibrate hikari, test cse_2018_02_28

Direct recall `0.00027`; detection-or-review `0.01330`; benign FPR `0.00080`; PR-AUC `0.50231`.

### robust_covariance: fit iot23, calibrate hikari, test cse_2018_02_28

Direct recall `0.08191`; detection-or-review `0.13019`; benign FPR `0.10374`; PR-AUC `0.48462`.

### local_outlier_factor: fit iot23, calibrate hikari, test cse_2018_02_28

Direct recall `0.07008`; detection-or-review `0.21410`; benign FPR `0.07058`; PR-AUC `0.50289`.

### one_class_svm: fit iot23, calibrate hikari, test cse_2018_02_28

Direct recall `0.15652`; detection-or-review `0.36729`; benign FPR `0.17459`; PR-AUC `0.49641`.

### denoising_autoencoder: fit iot23, calibrate hikari, test cse_2018_02_28

Direct recall `0.15864`; detection-or-review `0.28856`; benign FPR `0.17353`; PR-AUC `0.49775`.

### isolation_forest: fit hikari, calibrate cse_2018_02_28, test iot23

Direct recall `0.00357`; detection-or-review `0.00459`; benign FPR `0.01507`; PR-AUC `0.56856`.

### robust_covariance: fit hikari, calibrate cse_2018_02_28, test iot23

Direct recall `0.00000`; detection-or-review `0.00000`; benign FPR `0.00000`; PR-AUC `0.46961`.

### local_outlier_factor: fit hikari, calibrate cse_2018_02_28, test iot23

Direct recall `0.00000`; detection-or-review `0.00000`; benign FPR `0.00000`; PR-AUC `0.66860`.

### one_class_svm: fit hikari, calibrate cse_2018_02_28, test iot23

Direct recall `0.00000`; detection-or-review `0.00000`; benign FPR `0.00024`; PR-AUC `0.43395`.

### denoising_autoencoder: fit hikari, calibrate cse_2018_02_28, test iot23

Direct recall `0.00000`; detection-or-review `0.00000`; benign FPR `0.00049`; PR-AUC `0.25123`.

### isolation_forest: fit cse_2018_02_28, calibrate hikari, test iot23

Direct recall `0.00306`; detection-or-review `0.00357`; benign FPR `0.03330`; PR-AUC `0.56405`.

### robust_covariance: fit cse_2018_02_28, calibrate hikari, test iot23

Direct recall `0.00510`; detection-or-review `0.72435`; benign FPR `0.05445`; PR-AUC `0.51316`.

### local_outlier_factor: fit cse_2018_02_28, calibrate hikari, test iot23

Direct recall `0.09393`; detection-or-review `0.11077`; benign FPR `0.06368`; PR-AUC `0.30586`.

### one_class_svm: fit cse_2018_02_28, calibrate hikari, test iot23

Direct recall `0.00000`; detection-or-review `0.00459`; benign FPR `0.00122`; PR-AUC `0.44833`.

### denoising_autoencoder: fit cse_2018_02_28, calibrate hikari, test iot23

Direct recall `0.00357`; detection-or-review `0.00459`; benign FPR `0.00267`; PR-AUC `0.42727`.

## Limitations

- Class sampling and exact-vector deduplication prevent representative false-alerts-per-hour estimates.
- Anomaly results are not classifier probabilities; ECE and Brier are not applicable.
- This experiment does not include temporal Schema B or signature evidence.
