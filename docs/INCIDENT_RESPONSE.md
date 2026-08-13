# Incident response

AegisFlow is detection and investigation software. It never blocks automatically; any
containment action belongs to the organization's separately authorized response process.

## Triage

1. Record the incident ID, alert IDs, first/last timestamps, current model checksum,
   sensor IDs, deployment version, and analyst identity.
2. Inspect the durable timeline, signatures, reasons, risk/severity changes, endpoint
   sets, and queue/system health. Treat AI text as optional advisory prose only.
3. Distinguish a traffic incident from a platform incident: authentication failures,
   queue growth, schema errors, stale models, database errors, or clock drift can affect
   evidence quality.
4. Acknowledge alerts and add bounded notes through authenticated analyst actions. Do not
   rewrite original detections or label suspicious traffic benign to clear an incident.
5. Escalate containment recommendations to the authorized network/security owner. Record
   their independent decision; AegisFlow supplies no blocking path.

## Evidence preservation

Preserve audit rows, model/evaluation checksums, release manifest, aggregate queue and
latency metrics, relevant sanitized logs, and authorized source captures under the
organization's evidence policy. Never copy credentials or packet payloads into notes,
issues, logs, or this repository. Raw addresses require explicit export authorization;
prefer pseudonymized exports.

## Platform compromise or bad model

Disable external access at the gateway, preserve logs, rotate affected credentials at
their authority, and use a clean deployment. For a bad model, stop or drain detectors,
invoke the audited model rollback, restart all API/detector replicas, verify exact version
convergence, and replay only the isolated synthetic smoke. If artifact integrity cannot
be established, leave detection unavailable and visible.

## Closure

Record the timeline, scope, decisions, data gaps, false-positive/false-negative impact,
recovery measurements, checksums, follow-up owner, and whether baselines or model evidence
were affected. Analyst feedback remains a candidate input only; it cannot retrain or
promote a model automatically.
