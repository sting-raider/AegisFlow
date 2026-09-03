# Independent-benign origin evidence and limitations

Source: `docs/research-v2/registered-results/DEV2-ORIGIN-002.json`, executed from clean
commit `825efd123b711334e17e5fdc738a50281f8d8f95` under the protocol registered in
`df7df95`. This is an origin diagnostic, not detector training or attack evaluation.

## Findings

Three frozen FAMILY-002 encoders were tested on 392 benign inputs from hp4, hp5 and
capture 20-1, all excluded from encoder fitting by exact ID/input checks. Mean
five-fold balanced origin accuracy crosses the fixed 0.90 warning for every encoder
under at least one declared probe transform:

- C&C-excluded encoder: 0.93908 with quantile-normal probe preprocessing.
- DDoS-excluded encoder: 0.90594 with standard preprocessing.
- Port-scan-excluded encoder: 0.90604 clipped-robust and 0.91344 quantile-normal.

Thus the learned embeddings retain detectable benign environment information. The
quantile-normal transform is applied to the origin probe only, not to the detector.
This does not establish that origin identity alone caused each detection error.

Full aggregate features exceed 0.90 for all four transforms (0.90064–0.91028). Removing
categorical/missingness indicators reduces the numerical-core score to 0.89137–0.89868,
still close to the warning. It is not evidence of domain invariance or permission to
select a model. Raw sequence and sequence-plus-aggregate views yield about 0.876–0.882
where evaluable; those numbers likewise do not measure unknown-attack recall.

## Explicit coverage failures

Of 32 declared view/transform combinations, 24 complete all five folds, four have
incomplete folds, and four share an ineligible mask-only grouping. Across the 140
attempted probe folds, 123 retain numeric fitted artifacts; 15 fail to converge at the
unchanged 3,000-iteration limit and two develop train/test input aliases after numeric
transformation. These failures are not assigned zero, chance accuracy, or a partial
five-fold mean. The mask-only view has 12 exact groups, seven shared by different
origins; the fixed grouped split loses an origin in a partition. No new seed or
alternative split was tried to obtain a score.

All inputs are benign, but there are only three captures and capture 20-1 contributes
30 distinct full inputs. Within-capture correlation can make CV optimistic. Different
views use different exact-vector groups, so cross-view scores are not perfectly paired
statistical comparisons. Only the declared linear probe was used. The mask control is
inconclusive, not evidence that missingness is harmless. Imputation comparisons on the
broader development corpus and cross-environment attack/ablation studies remain open.

## Repeated attempt and measured costs

The first attempt (`53a62eb`, 89.676 seconds) preserved scores, errors and memory but
omitted elapsed fit time for failed folds. Its unchanged report is retained as
`DEV2-ORIGIN-002-cost-incomplete.json`, SHA-256
`0f6f95b72f7b120c7f514a50b468112084df99bc2f63b664a24798067cc017c2`.
A controlled nonconverging fixture reproduced the defect. Only the exception-path timer
was fixed; the repeat used the same registration, data, folds, encoders and solver limits.

The cost-complete repeat took 87.233 seconds. Its inputs, grouping, scores, outcomes and
all 123 numeric probe-artifact hashes exactly match the first attempt, enforced by the
publication guard. Successful probe fits total 7.292 seconds; unsuccessful attempts total
13.169 seconds (including preprocessing before transformed-alias refusal). Sampled process
RSS ranges 349,708,288–350,560,256 bytes across fold samplers; this includes loaded data and
frozen models. Reported inference timings cover prebuilt-view transformation plus origin
prediction, not feature/encoder construction or durable NIDS throughput.

## Consequence

Do not promote a candidate based on a raw-feature origin score below 0.90 while ignoring
learned-embedding warnings or unevaluable controls. Preserve the failed FAMILY-002
detection result. Continue the remaining detector ablations, missingness study and
registered cross-environment validation; do not tune frozen final evidence. The deployed
approved-site baseline and operational failure/partitioning acceptance requirements are
still separate unfinished work.
