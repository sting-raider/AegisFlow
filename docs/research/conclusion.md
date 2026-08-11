# Development model conclusion

## Verdict

The current AegisFlow flow-level challenger program receives a **development scientific
NO-GO**. No tested representation/model/calibration configuration meets the predeclared
development objectives, so no challenger is eligible to be locked or run against the
frozen final reports.

This is not a claim that network intrusion detection is impossible. It is evidence that
the available portable aggregate-flow contract, the current bounded temporal context,
and the reviewed development environments do not support a robust universal detector at
the required benign false-positive and unseen-behavior recall levels.

## Evidence chain

- Full portable Schema A remains blocked by 0.95416 balanced dataset-origin accuracy. The
  nine-feature numerical core clears the shortcut threshold at 0.68428.
- Four supervised baselines fail cross-environment transfer. The best mean model has only
  3.64% malicious recall in its worst environment and 18.20% worst benign FPR.
- Five benign-only anomaly families all have zero or near-zero worst-environment unknown
  recall. The strongest mean detection-or-review result reaches only 15.81% and transfers
  with 10.85% worst benign FPR.
- The full temporal hybrid reaches 52.14% mean detection-or-review, but only 0.067% in its
  worst family/calibration orientation and 1.61% worst benign FPR.
- Aggregate errors show that zero/one-packet and zero-duration command-and-control flows
  carry too little observable behavior, while calibration choice causes large DDoS and
  port-scan swings.
- The final predeclared cross-fitted calibration ensemble removes arbitrary benign-device
  orientation. It still has 0% direct command-and-control detection, 4.10% port-scan
  detection-or-review, 0% worst direct unknown recall, and 1.09% worst benign FPR.

## Why the frozen reports remain sealed

The protocol requires candidate selection, code/configuration locking, and threshold
locking from development evidence before a single final run. `DEV-CAL-001` fails before
that boundary. Running the frozen matrix anyway would spend final evidence on an
ineligible model and invite test-guided iteration. The existing frozen reports continue
to reject only the deployed smoke model; they are not reused to tune or characterize this
failed challenger family.

## Strongest next research direction

Further opportunistic classifier or anomaly-model search over the same fields is not
supported by the evidence. A future research program should first add independently
reviewed development environments with full temporal prerequisites and richer observable
semantics, such as packet-sequence timing/size summaries, connection-state transitions,
DNS/TLS metadata that passes privacy review, or explicitly approved site/peer-group
baselines. It must repeat origin diagnostics and held-environment evaluation before any
new final candidate is considered.

Environment-aware observation mode remains a useful engineering direction only when
benign calibration traffic is human-approved. Suspicious or unreviewed traffic must never
enter that baseline automatically, and rollback must remain available.

## Safe claim

AegisFlow is a tested real-time NIDS engineering and evaluation platform with a
scientifically documented negative model result. It is not a validated production
detector.
