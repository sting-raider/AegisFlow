# Independent-benign origin audit

Executed commit: `825efd123b711334e17e5fdc738a50281f8d8f95`. Development diagnostic only.

Mean balanced accuracy for predicting one of three benign capture origins.
The fixed warning threshold is 0.90; a lower score does not prove invariance.

| View | Standard | Robust | Clipped robust | Quantile normal |
|---|---:|---:|---:|---:|
| aggregate | 0.9103 | 0.9103 | 0.9067 | 0.9006 |
| numerical_core | 0.8969 | 0.8969 | 0.8987 | 0.8914 |
| sequence_mask | 0.8820 | unevaluable | unevaluable | 0.8763 |
| sequence_aggregate | 0.8819 | unevaluable | unevaluable | 0.8820 |
| missingness_only | unevaluable | unevaluable | unevaluable | unevaluable |
| embedding_c_and_c | 0.8948 | 0.8836 | 0.8819 | 0.9391 |
| embedding_ddos | 0.9059 | 0.8985 | 0.8949 | 0.8893 |
| embedding_port_scan | 0.8930 | 0.8985 | 0.9060 | 0.9134 |

Inputs: 181 hp4, 181 hp5, 30 capture-20 benign records; none entered encoder fitting.
Grouped-fold/convergence failures remain explicit; no detector was retrained.

Regenerate with `python -m scripts.verify_registered_origin --markdown`.
