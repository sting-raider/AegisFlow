# DEV2-CONTEXT-001 registered result

- Execution commit: `8071496690ce9d3150cd1209d7035b29584502bd`
- Report SHA-256: `e5bc778271823a5b2bc30d60bb7aa125212fad58863a73e6c81dbeb921540909`
- Runtime: 61.24 seconds
- Coverage: 36/36 models and 72/72 site evaluations
- Registered conclusion: `null_no_detectable_causal_benefit_under_registered_rule`
- Candidate selected: no

## Paired registered comparisons

| Target | Site orientation | Control | Attack direct Δ (95%) | Attack detect/review Δ (95%) | Benign FPR Δ (95%) | Qualifies |
|---|---|---|---:|---:|---:|:---:|
| 20-1 | 4-1 → 5-1 | shuffled_context | -4.76% [-23.81%, 14.29%] | -14.29% [-52.38%, 19.05%] | 2.58% [0.37%, 4.97%] | no |
| 20-1 | 4-1 → 5-1 | no_context | -14.29% [-42.86%, 0.00%] | -52.38% [-71.43%, -33.33%] | 0.55% [-1.29%, 2.39%] | no |
| 20-1 | 5-1 → 4-1 | shuffled_context | -19.05% [-28.57%, -9.52%] | -14.29% [-28.57%, 4.76%] | -0.47% [-7.09%, 6.38%] | no |
| 20-1 | 5-1 → 4-1 | no_context | -19.05% [-38.10%, 0.00%] | -61.90% [-66.67%, -52.38%] | 15.84% [10.87%, 20.80%] | no |
| 34-1 | 4-1 → 5-1 | shuffled_context | -26.94% [-27.50%, -26.43%] | -13.32% [-14.06%, -12.58%] | 1.10% [0.00%, 2.39%] | no |
| 34-1 | 4-1 → 5-1 | no_context | 0.01% [-0.06%, 0.08%] | -77.82% [-78.46%, -77.18%] | 0.18% [-0.74%, 1.29%] | no |
| 34-1 | 5-1 → 4-1 | shuffled_context | -28.31% [-28.76%, -27.82%] | -14.67% [-15.43%, -13.89%] | -8.27% [-10.64%, -5.91%] | no |
| 34-1 | 5-1 → 4-1 | no_context | 0.06% [0.01%, 0.11%] | -37.07% [-37.85%, -36.31%] | 0.24% [0.00%, 0.71%] | no |
| 8-1 | 4-1 → 5-1 | shuffled_context | 33.19% [33.07%, 33.28%] | 0.00% [0.00%, 0.00%] | -3.68% [-6.26%, -1.10%] | no |
| 8-1 | 4-1 → 5-1 | no_context | 33.32% [33.25%, 33.37%] | -33.33% [-33.33%, -33.33%] | 0.55% [-0.18%, 1.66%] | no |
| 8-1 | 5-1 → 4-1 | shuffled_context | 33.33% [33.27%, 33.40%] | 66.55% [66.46%, 66.63%] | -8.27% [-13.71%, -3.07%] | yes |
| 8-1 | 5-1 → 4-1 | no_context | 33.37% [33.33%, 33.41%] | -0.05% [-0.11%, 0.00%] | 7.80% [5.44%, 10.17%] | no |

## Descriptive mean across 18 site entries per view

These are correlated entry means, not independent estimates.

| View | Attack direct | Attack detect/review | Independent benign FPR | Independent benign review |
|---|---:|---:|---:|---:|
| causal_context | 12.79% | 39.34% | 5.72% | 19.23% |
| shuffled_context | 14.88% | 37.67% | 8.56% | 20.97% |
| no_context | 7.22% | 83.09% | 1.53% | 20.89% |
| non_causal_reference | 71.43% | 97.62% | 24.99% | 62.66% |

## Decision

Causal context qualified in 1/6 strata versus shuffled context and 0/6 versus no context. The registered rule requires at least 5/6 against each control, with every target and site orientation represented.

Result: **NULL for detectable causal benefit in this development study.** No candidate, production claim, frozen-test access, or deployment change is authorized.
