import { useEffect, useMemo, useRef, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  Bar,
  BarChart,
  CartesianGrid,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis
} from "recharts";
import { alertSocketProtocols, alertSocketUrl, api, flowExportUrl } from "./api";
import type {
  Alert,
  DriftEvent,
  Flow,
  Host,
  Incident,
  ModelVersion,
  SystemStatus
} from "./types";

type View = "overview" | "alerts" | "incidents" | "flows" | "hosts" | "models" | "system";

const views: { id: View; label: string; key: string }[] = [
  { id: "overview", label: "Overview", key: "01" },
  { id: "alerts", label: "Live alerts", key: "02" },
  { id: "incidents", label: "Incidents", key: "03" },
  { id: "flows", label: "Flow explorer", key: "04" },
  { id: "hosts", label: "Hosts", key: "05" },
  { id: "models", label: "Models & drift", key: "06" },
  { id: "system", label: "System health", key: "07" }
];

function useOperationsData(paused: boolean) {
  const queryClient = useQueryClient();
  const pausedRef = useRef(paused);
  useEffect(() => { pausedRef.current = paused; }, [paused]);
  const alerts = useQuery({ queryKey: ["alerts"], queryFn: () => api.alerts("?limit=200") });
  const incidents = useQuery({ queryKey: ["incidents"], queryFn: api.incidents });
  const flows = useQuery({ queryKey: ["flows"], queryFn: () => api.flows("?limit=200") });
  const hosts = useQuery({ queryKey: ["hosts"], queryFn: api.hosts });
  const models = useQuery({ queryKey: ["models"], queryFn: api.models });
  const drift = useQuery({ queryKey: ["drift"], queryFn: api.drift });
  const status = useQuery({
    queryKey: ["status"],
    queryFn: api.status,
    refetchInterval: 5_000
  });
  const [connected, setConnected] = useState(false);

  useEffect(() => {
    let socket: WebSocket | undefined;
    let retry: number | undefined;
    let stopped = false;
    const connect = () => {
      socket = new WebSocket(alertSocketUrl(), alertSocketProtocols());
      socket.onopen = () => setConnected(true);
      socket.onmessage = (event) => {
        const payload = JSON.parse(event.data) as { type: string; items: Alert[] };
        if (payload.type === "alerts" && !pausedRef.current) {
          queryClient.setQueryData(["alerts"], {
            items: payload.items,
            count: payload.items.length
          });
        }
      };
      socket.onclose = () => {
        setConnected(false);
        if (!stopped) retry = window.setTimeout(connect, 1_500);
      };
    };
    connect();
    return () => {
      stopped = true;
      if (retry) window.clearTimeout(retry);
      socket?.close();
    };
  }, [queryClient]);

  return { alerts, incidents, flows, hosts, models, drift, status, connected };
}

function Badge({ value }: { value: string }) {
  return <span className={`badge badge--${value}`}>{value.replaceAll("_", " ")}</span>;
}

function State({
  loading,
  error,
  empty,
  children
}: {
  loading: boolean;
  error: Error | null;
  empty: boolean;
  children: React.ReactNode;
}) {
  if (loading) return <div className="state">Reading the event ledger…</div>;
  if (error) return <div className="state state--error">Data is unavailable. Check API readiness.</div>;
  if (empty) return <div className="state">No records match this view yet.</div>;
  return children;
}

function Metric({ label, value, note }: { label: string; value: string | number; note: string }) {
  return (
    <article className="metric">
      <span>{label}</span>
      <strong>{value}</strong>
      <small>{note}</small>
    </article>
  );
}

function Flowline({ alerts }: { alerts: Alert[] }) {
  return (
    <section className="flowline" aria-label="Recent detection flowline">
      <div className="flowline__legend">
        <span>Oldest</span>
        <strong>Detection flowline</strong>
        <span>Now</span>
      </div>
      <div className="flowline__track">
        {alerts
          .slice()
          .reverse()
          .slice(-24)
          .map((alert) => (
            <span
              key={alert.id}
              className={`flowline__mark flowline__mark--${alert.severity}`}
              style={{ height: `${Math.max(18, alert.risk)}%` }}
              title={`${alert.verdict}: risk ${alert.risk}`}
            />
          ))}
        {alerts.length === 0 && <span className="flowline__idle">Waiting for validated flows</span>}
      </div>
    </section>
  );
}

function Overview({
  alerts,
  incidents,
  flows,
  models,
  status,
  drift
}: {
  alerts: Alert[];
  incidents: Incident[];
  flows: Flow[];
  models: ModelVersion[];
  status?: SystemStatus;
  drift: DriftEvent[];
}) {
  const severityData = useMemo(
    () =>
      ["critical", "high", "medium", "low"].map((severity) => ({
        severity,
        alerts: alerts.filter((item) => item.severity === severity).length
      })),
    [alerts]
  );
  const unknown = alerts.filter((item) => item.verdict === "suspicious_unknown").length;
  const known = alerts.filter((item) => item.verdict === "known_attack").length;
  const protocolData = useMemo(() => {
    const counts = new Map<string, number>();
    flows.forEach((flow) => counts.set(flow.protocol, (counts.get(flow.protocol) ?? 0) + 1));
    return [...counts].map(([protocol, count]) => ({ protocol, count })).sort((a, b) => b.count - a.count);
  }, [flows]);
  const sourceHosts = useMemo(() => rankedHosts(flows.map((flow) => flow.src_ip)), [flows]);
  const destinationHosts = useMemo(() => rankedHosts(flows.map((flow) => flow.dst_ip)), [flows]);
  const throughput = observedFlowRate(flows);
  return (
    <>
      <Flowline alerts={alerts} />
      <div className="metric-grid">
        <Metric label="Flow throughput" value={`${throughput.toFixed(2)}/s`} note={`${flows.length} validated records`} />
        <Metric label="Open incidents" value={incidents.filter((i) => i.status !== "closed").length} note="deterministic grouping" />
        <Metric label="Unknown-behaviour flags" value={unknown} note="statistical, not confirmed" />
        <Metric label="Sensors ready" value={status?.sensors ?? "—"} note={`${status?.mode ?? "unknown"} mode`} />
      </div>
      <div className="overview-grid">
        <section className="panel">
          <header><span>Alert pressure</span><small>by severity</small></header>
          <div className="chart">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={severityData}>
                <CartesianGrid stroke="#294651" vertical={false} />
                <XAxis dataKey="severity" stroke="#89a2ad" />
                <YAxis allowDecimals={false} stroke="#89a2ad" />
                <Tooltip cursor={{ fill: "#17313d" }} />
                <Bar
                  dataKey="alerts"
                  fill="#ff735c"
                  isAnimationActive={false}
                  radius={[2, 2, 0, 0]}
                />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </section>
        <section className="panel">
          <header><span>Detection character</span><small>known vs unknown</small></header>
          <div className="duel">
            <div><span>Known</span><strong>{known}</strong><small>classifier or signature evidence</small></div>
            <div><span>Unknown</span><strong>{unknown}</strong><small>statistical review flags</small></div>
          </div>
          <header className="subhead"><span>Protocol distribution</span><small>stored flows</small></header>
          <div className="chart chart--compact">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={protocolData.slice(0, 6)} layout="vertical">
                <CartesianGrid stroke="#294651" horizontal={false} />
                <XAxis type="number" allowDecimals={false} stroke="#89a2ad" />
                <YAxis type="category" dataKey="protocol" width={54} stroke="#89a2ad" />
                <Tooltip cursor={{ fill: "#17313d" }} />
                <Bar dataKey="count" fill="#53c7c2" isAnimationActive={false} />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </section>
        <section className="panel model-card">
          <header><span>Production model</span><small>integrity checked</small></header>
          {models[0] ? (
            <>
              <strong>{models[0].model_name}</strong>
              <div className="model-card__version">v{models[0].version}</div>
              <dl>
                <div><dt>Feature schema</dt><dd>{models[0].metadata.feature_schema_version}</dd></div>
                <div><dt>Classes</dt><dd>{models[0].metadata.model_classes.join(", ")}</dd></div>
              </dl>
            </>
          ) : <p>No production model loaded.</p>}
        </section>
      </div>
      <div className="overview-grid overview-grid--lower">
        <RankedPanel title="Top sources" note="flow origin" items={sourceHosts} />
        <RankedPanel title="Top destinations" note="flow target" items={destinationHosts} />
        <section className="panel ledger-panel">
          <header><span>Operations ledger</span><small>current state</small></header>
          <dl>
            <div><dt>Queue work</dt><dd>{(status?.queue.lag ?? 0) + (status?.queue.pending ?? 0)}</dd></div>
            <div><dt>Sensor records</dt><dd>{status?.sensors ?? "not reported"}</dd></div>
            <div><dt>Recent drift</dt><dd>{drift.length}</dd></div>
            <div><dt>Latest signal</dt><dd>{drift[0]?.signal.replaceAll("_", " ") ?? "none"}</dd></div>
          </dl>
        </section>
      </div>
    </>
  );
}

function rankedHosts(values: string[]) {
  const counts = new Map<string, number>();
  values.forEach((value) => counts.set(value, (counts.get(value) ?? 0) + 1));
  return [...counts].map(([label, count]) => ({ label, count })).sort((a, b) => b.count - a.count).slice(0, 5);
}

function RankedPanel({ title, note, items }: { title: string; note: string; items: Array<{ label: string; count: number }> }) {
  const maximum = Math.max(1, ...items.map((item) => item.count));
  return <section className="panel ranked-panel"><header><span>{title}</span><small>{note}</small></header>
    {items.length ? <ol>{items.map((item) => <li key={item.label}><span className="mono">{item.label}</span><i style={{ width: `${(item.count / maximum) * 100}%` }} /><strong>{item.count}</strong></li>)}</ol> : <div className="state">No host activity recorded.</div>}
  </section>;
}

function observedFlowRate(flows: Flow[]): number {
  if (flows.length < 2) return flows.length;
  const timestamps = flows.map((flow) => new Date(flow.timestamp_start).getTime());
  const seconds = Math.max(1, (Math.max(...timestamps) - Math.min(...timestamps)) / 1000);
  return flows.length / seconds;
}

function AlertTable({
  alerts,
  onSelect,
  paused,
  setPaused
}: {
  alerts: Alert[];
  onSelect: (alert: Alert) => void;
  paused: boolean;
  setPaused: (paused: boolean) => void;
}) {
  const [severity, setSeverity] = useState("all");
  const [verdict, setVerdict] = useState("all");
  const [search, setSearch] = useState("");
  const shown = alerts.filter((alert) =>
    (severity === "all" || alert.severity === severity) &&
    (verdict === "all" || alert.verdict === verdict) &&
    `${alert.flow.src_ip} ${alert.flow.dst_ip} ${alert.flow.protocol} ${alert.detection.reason_codes.join(" ")}`.toLowerCase().includes(search.toLowerCase())
  );
  return (
    <>
      <div className="toolbar" aria-label="Alert controls">
        <label>Search alerts<input value={search} onChange={(event) => setSearch(event.target.value)} placeholder="Endpoint or reason code" /></label>
        <label>Severity<select value={severity} onChange={(event) => setSeverity(event.target.value)}><option value="all">All severities</option><option value="critical">Critical</option><option value="high">High</option><option value="medium">Medium</option><option value="low">Low</option></select></label>
        <label>Verdict<select value={verdict} onChange={(event) => setVerdict(event.target.value)}><option value="all">All verdicts</option><option value="known_attack">Known attack</option><option value="suspicious_unknown">Suspicious unknown</option><option value="needs_review">Needs review</option></select></label>
        <button className={`stream-toggle ${paused ? "is-paused" : ""}`} onClick={() => setPaused(!paused)}>{paused ? "Resume live feed" : "Pause live feed"}</button>
      </div>
      <p className="result-count">Showing {shown.length} of {alerts.length} alerts{paused ? " · live updates paused" : ""}</p>
      <div className="table-wrap">
      <table>
        <thead><tr><th>Time</th><th>Verdict</th><th>Risk</th><th>Route</th><th>Protocol</th><th>Evidence</th><th>State</th></tr></thead>
        <tbody>
          {shown.map((alert) => (
            <tr key={alert.id} onClick={() => onSelect(alert)} tabIndex={0} onKeyDown={(event) => event.key === "Enter" && onSelect(alert)}>
              <td>{new Date(alert.created_at).toLocaleTimeString()}</td>
              <td><Badge value={alert.verdict} /></td>
              <td><span className={`risk risk--${alert.severity}`}>{alert.risk.toFixed(0)}</span></td>
              <td className="mono">{alert.flow.src_ip} → {alert.flow.dst_ip}:{alert.flow.dst_port}</td>
              <td>{alert.flow.protocol}</td>
              <td>{alert.detection.signature_score > 0 ? "signature + model" : "model"}</td>
              <td>{alert.acknowledged ? "acknowledged" : "new"}</td>
            </tr>
          ))}
        </tbody>
      </table>
      </div>
    </>
  );
}

function AlertDetail({ alert, close }: { alert: Alert; close: () => void }) {
  const [disposition, setDisposition] = useState("requires_investigation");
  const [comment, setComment] = useState("");
  const mutation = useMutation({
    mutationFn: () => api.feedback(alert.id, { disposition, comment })
  });
  const queryClient = useQueryClient();
  const acknowledgement = useMutation({
    mutationFn: () => api.acknowledge(alert.id),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["alerts"] })
  });
  return (
    <aside className="drawer" aria-label="Alert detail">
      <button className="drawer__close" onClick={close} aria-label="Close alert detail">×</button>
      <p className="eyebrow">Detection evidence</p>
      <h2>{alert.verdict.replaceAll("_", " ")}</h2>
      <div className="risk-orbit"><span>{alert.risk.toFixed(0)}</span><small>risk / 100</small></div>
      <p>{alert.detection.explanation}</p>
      <div className="drawer-actions">
        <button className="primary" disabled={alert.acknowledged || acknowledgement.isPending || acknowledgement.isSuccess} onClick={() => acknowledgement.mutate()}>
          {alert.acknowledged || acknowledgement.isSuccess ? "Acknowledged" : "Acknowledge alert"}
        </button>
        <span className="mono">model {alert.detection.classifier_model_version}</span>
      </div>
      <div className="signal-grid">
        <Metric label="Known" value={`${(alert.detection.known_attack_probability * 100).toFixed(0)}%`} note="classifier" />
        <Metric label="Anomaly" value={`${(alert.detection.anomaly_score * 100).toFixed(0)}%`} note="benign baseline" />
        <Metric label="Signature" value={`${(alert.detection.signature_score * 100).toFixed(0)}%`} note="rules" />
      </div>
      <h3>Reason codes</h3>
      <div className="reason-list">{alert.detection.reason_codes.map((reason) => <code key={reason}>{reason}</code>)}</div>
      <form onSubmit={(event) => { event.preventDefault(); mutation.mutate(); }}>
        <label>Analyst disposition
          <select value={disposition} onChange={(event) => setDisposition(event.target.value)}>
            <option value="requires_investigation">Requires investigation</option>
            <option value="true_positive">True positive</option>
            <option value="false_positive">False positive</option>
            <option value="benign_new_behaviour">Benign new behaviour</option>
            <option value="duplicate">Duplicate</option>
          </select>
        </label>
        <label>Note
          <textarea value={comment} onChange={(event) => setComment(event.target.value)} placeholder="Record what you observed" />
        </label>
        <button className="primary" disabled={mutation.isPending}>Record feedback</button>
        {mutation.isSuccess && <span className="form-success">Feedback recorded without changing the detection.</span>}
        {mutation.isError && <span className="form-error">Feedback was not recorded. Check API access.</span>}
      </form>
    </aside>
  );
}

function Incidents({ incidents }: { incidents: Incident[] }) {
  const [selected, setSelected] = useState<Incident | null>(null);
  const [statusChoice, setStatusChoice] = useState("investigating");
  const [analystNote, setAnalystNote] = useState("");
  const queryClient = useQueryClient();
  const detail = useQuery({
    queryKey: ["incident", selected?.id],
    queryFn: () => api.incident(selected!.id),
    enabled: selected !== null
  });
  const explanation = useQuery({
    queryKey: ["incident-explanation", selected?.id],
    queryFn: () => api.incidentExplanation(selected!.id),
    enabled: selected !== null,
    retry: false
  });
  const statusMutation = useMutation({
    mutationFn: () => api.setIncidentStatus(selected!.id, statusChoice),
    onSuccess: async () => {
      await Promise.all([
        queryClient.invalidateQueries({ queryKey: ["incidents"] }),
        queryClient.invalidateQueries({ queryKey: ["incident", selected?.id] }),
        queryClient.invalidateQueries({ queryKey: ["incident-explanation", selected?.id] })
      ]);
    }
  });
  const noteMutation = useMutation({
    mutationFn: () => api.addIncidentNote(selected!.id, analystNote),
    onSuccess: async () => {
      setAnalystNote("");
      await queryClient.invalidateQueries({ queryKey: ["incident", selected?.id] });
    }
  });
  const current = detail.data ?? selected;
  const open = (incident: Incident) => {
    setSelected(incident);
    setStatusChoice(incident.status === "open" ? "investigating" : incident.status);
  };
  return <>
    <div className="card-grid">{incidents.map((incident) => (
      <article className="incident-card" key={incident.id}>
        <div><Badge value={incident.severity} /><span className="incident-card__status">{incident.status}</span></div>
        <h3>{incident.title}</h3>
        <p>{incident.alert_ids.length} related alert{incident.alert_ids.length === 1 ? "" : "s"}</p>
        <ul>{incident.grouping_reasons.map((reason) => <li key={reason}>{reason}</li>)}</ul>
        <small>Updated {new Date(incident.updated_at).toLocaleString()}</small>
        <button className="primary incident-card__explain" onClick={() => open(incident)}>
          Open incident
        </button>
      </article>
    ))}</div>
    {selected && current && <aside className="drawer" aria-label="Incident detail">
      <button className="drawer__close" onClick={() => setSelected(null)} aria-label="Close incident detail">×</button>
      <p className="eyebrow">Correlated alert timeline</p>
      <h2>{current.title}</h2>
      <div className="signal-grid incident-summary">
        <Metric label="Alerts" value={current.alert_count} note={`${current.acknowledged_alerts} acknowledged`} />
        <Metric label="Max risk" value={current.max_risk.toFixed(0)} note={current.severity} />
        <Metric label="Escalations" value={current.escalation_count} note="deterministic" />
      </div>
      <form className="incident-status" onSubmit={(event) => { event.preventDefault(); statusMutation.mutate(); }}>
        <label>Incident status
          <select value={statusChoice} onChange={(event) => setStatusChoice(event.target.value)}>
            <option value="open">Open</option>
            <option value="investigating">Investigating</option>
            <option value="contained">Contained</option>
            <option value="closed">Closed</option>
          </select>
        </label>
        <button className="primary" disabled={statusMutation.isPending}>Update status</button>
        {statusMutation.isSuccess && <span className="form-success">Incident status updated.</span>}
        {statusMutation.isError && <span className="form-error">Status was not updated.</span>}
      </form>
      <h3>Correlation evidence</h3>
      <div className="reason-list">
        {current.grouping_reasons.map((reason) => <code key={reason}>{reason}</code>)}
        {current.attack_stages.map((stage) => <code key={stage}>{stage.replaceAll("_", " ")}</code>)}
      </div>
      <h3>Timeline</h3>
      <ol className="incident-timeline">{current.timeline.map((entry) => <li key={entry.alert_id}>
        <span className={`incident-timeline__mark incident-timeline__mark--${entry.severity}`} />
        <div><strong>{entry.attack_stage.replaceAll("_", " ")}</strong><small>{new Date(entry.timestamp).toLocaleString()}</small></div>
        <div className="mono">{entry.source_host} → {entry.destination_host}</div>
        <span className={`risk risk--${entry.severity}`}>{entry.risk.toFixed(0)}</span>
      </li>)}</ol>
      <h3>Analyst notes</h3>
      {current.analyst_notes?.length ? <ol className="event-ledger analyst-notes">{current.analyst_notes.map((note) => <li key={note.id}><div><strong>{note.actor}</strong><small>{new Date(note.timestamp).toLocaleString()}</small><p>{note.note}</p></div></li>)}</ol> : <div className="state">No analyst note has been recorded for this incident.</div>}
      <form onSubmit={(event) => { event.preventDefault(); noteMutation.mutate(); }}>
        <label>Add analyst note<textarea value={analystNote} required maxLength={2000} onChange={(event) => setAnalystNote(event.target.value)} placeholder="Record investigation context without packet payloads" /></label>
        <button className="primary" disabled={!analystNote.trim() || noteMutation.isPending}>Add note</button>
        {noteMutation.isSuccess && <span className="form-success">Analyst note added.</span>}
        {noteMutation.isError && <span className="form-error">Analyst note was not added.</span>}
      </form>
      <h3>Advisory explanation</h3>
      {explanation.isLoading && <div className="state">Generating an advisory explanation…</div>}
      {explanation.isError && <div className="state state--error">The optional provider is unavailable.</div>}
      {explanation.data && <section className="explanation">
        <div className="explanation__label">
          <Badge value={explanation.data.ai_generated ? "ai_generated" : "deterministic"} />
          <span>{explanation.data.provider}{explanation.data.cached ? " · cached" : ""}</span>
        </div>
        {explanation.data.fallback && <p className="limitation">Optional provider failed or was limited; deterministic fallback shown.</p>}
        <p>{explanation.data.text}</p>
        <h3>Limitations</h3>
        <ul>{explanation.data.limitations.map((item) => <li key={item}>{item}</li>)}</ul>
        <small>Generated {new Date(explanation.data.generated_at).toLocaleString()}</small>
      </section>}
    </aside>}
  </>;
}

function Flows({ flows }: { flows: Flow[] }) {
  const [filter, setFilter] = useState("");
  const [protocol, setProtocol] = useState("all");
  const [start, setStart] = useState("");
  const [end, setEnd] = useState("");
  const [page, setPage] = useState(0);
  const [selectedIds, setSelectedIds] = useState<string[]>([]);
  const [selected, setSelected] = useState<string | null>(null);
  const detail = useQuery({
    queryKey: ["flow", selected],
    queryFn: () => api.flow(selected!),
    enabled: selected !== null
  });
  const protocols = [...new Set(flows.map((flow) => flow.protocol))].sort();
  const shown = flows.filter((flow) => {
    const timestamp = new Date(flow.timestamp_start).getTime();
    return `${flow.src_ip} ${flow.dst_ip} ${flow.protocol} ${flow.dst_port}`.toLowerCase().includes(filter.toLowerCase()) &&
      (protocol === "all" || flow.protocol === protocol) &&
      (!start || timestamp >= new Date(start).getTime()) &&
      (!end || timestamp <= new Date(end).getTime());
  });
  const pageSize = 12;
  const pages = Math.max(1, Math.ceil(shown.length / pageSize));
  const pageItems = shown.slice(page * pageSize, (page + 1) * pageSize);
  const updateFilter = (setter: (value: string) => void, value: string) => {
    setter(value);
    setPage(0);
  };
  const toggle = (eventId: string) => setSelectedIds((current) =>
    current.includes(eventId) ? current.filter((item) => item !== eventId) : [...current, eventId]
  );
  return <>
    <div className="toolbar flow-toolbar">
      <label>Endpoint or port<input value={filter} onChange={(event) => updateFilter(setFilter, event.target.value)} placeholder="10.20.0.15 or 443" /></label>
      <label>Protocol<select value={protocol} onChange={(event) => updateFilter(setProtocol, event.target.value)}><option value="all">All protocols</option>{protocols.map((item) => <option key={item}>{item}</option>)}</select></label>
      <label>From<input type="datetime-local" value={start} onChange={(event) => updateFilter(setStart, event.target.value)} /></label>
      <label>To<input type="datetime-local" value={end} onChange={(event) => updateFilter(setEnd, event.target.value)} /></label>
      <a className={`export ${selectedIds.length ? "" : "is-disabled"}`} href={selectedIds.length ? flowExportUrl(selectedIds) : undefined} download aria-disabled={!selectedIds.length}>Export selected ({selectedIds.length})</a>
    </div>
    <div className="table-wrap"><table><thead><tr><th><span className="sr-only">Select</span></th><th>Started</th><th>Source</th><th>Destination</th><th>Protocol</th><th>Packets</th><th>Bytes out / in</th></tr></thead>
      <tbody>{pageItems.map((flow) => <tr key={flow.event_id} onClick={() => setSelected(flow.event_id)} tabIndex={0} onKeyDown={(event) => event.key === "Enter" && setSelected(flow.event_id)}><td><input aria-label={`Select flow ${flow.event_id}`} type="checkbox" checked={selectedIds.includes(flow.event_id)} onClick={(event) => event.stopPropagation()} onChange={() => toggle(flow.event_id)} /></td><td>{new Date(flow.timestamp_start).toLocaleString()}</td><td className="mono">{flow.src_ip}:{flow.src_port}</td><td className="mono">{flow.dst_ip}:{flow.dst_port}</td><td>{flow.protocol}</td><td>{flow.packets_forward + flow.packets_reverse}</td><td>{flow.bytes_forward.toLocaleString()} / {flow.bytes_reverse.toLocaleString()}</td></tr>)}</tbody>
    </table></div>
    <div className="pagination"><button disabled={page === 0} onClick={() => setPage((value) => value - 1)}>Previous</button><span>Page {page + 1} of {pages} · {shown.length} flows</span><button disabled={page + 1 >= pages} onClick={() => setPage((value) => value + 1)}>Next</button></div>
    {selected && <aside className="drawer" aria-label="Flow detail">
      <button className="drawer__close" onClick={() => setSelected(null)} aria-label="Close flow detail">×</button>
      <p className="eyebrow">Validated flow record</p><h2>Flow evidence</h2>
      {detail.isLoading && <div className="state">Reading associated detection…</div>}
      {detail.isError && <div className="state state--error">Flow detail could not be loaded.</div>}
      {detail.data && <>
        <div className="route-block"><span className="mono">{detail.data.src_ip}:{detail.data.src_port}</span><i>→</i><span className="mono">{detail.data.dst_ip}:{detail.data.dst_port}</span></div>
        <div className="signal-grid"><Metric label="Duration" value={`${detail.data.duration_ms.toFixed(0)} ms`} note={detail.data.protocol} /><Metric label="Packet rate" value={detail.data.packet_rate.toFixed(2)} note="packets / second" /><Metric label="Byte rate" value={detail.data.byte_rate.toFixed(0)} note="bytes / second" /></div>
        <h3>Associated detection</h3>
        {detail.data.detection ? <><Badge value={detail.data.detection.verdict} /><p>{detail.data.detection.explanation}</p><div className="reason-list">{detail.data.detection.reason_codes.map((reason) => <code key={reason}>{reason}</code>)}</div></> : <p className="limitation">No detection result is associated with this flow.</p>}
        <h3>Feature details</h3>
        <dl className="feature-ledger">
          <div><dt>Packets forward / reverse</dt><dd>{detail.data.packets_forward} / {detail.data.packets_reverse}</dd></div>
          <div><dt>Bytes forward / reverse</dt><dd>{detail.data.bytes_forward} / {detail.data.bytes_reverse}</dd></div>
          <div><dt>Packet length mean / std</dt><dd>{detail.data.packet_length_mean.toFixed(2)} / {detail.data.packet_length_std.toFixed(2)}</dd></div>
          <div><dt>IAT mean / std</dt><dd>{detail.data.iat_mean.toFixed(2)} / {detail.data.iat_std.toFixed(2)}</dd></div>
          <div><dt>TCP SYN / ACK / FIN / RST</dt><dd>{detail.data.tcp_syn_count} / {detail.data.tcp_ack_count} / {detail.data.tcp_fin_count} / {detail.data.tcp_rst_count}</dd></div>
          <div><dt>Extractor</dt><dd>{detail.data.source_adapter} · {detail.data.feature_extractor_version}</dd></div>
        </dl>
        <h3>Signatures</h3>
        {detail.data.signatures.length ? detail.data.signatures.map((signature) => <p className="limitation" key={signature.signature_id}>{signature.signature_name} · {signature.category}</p>) : <p>No correlated signature event.</p>}
      </>}
    </aside>}
  </>;
}

function Hosts({ hosts, flows, alerts }: { hosts: Host[]; flows: Flow[]; alerts: Alert[] }) {
  const [selected, setSelected] = useState<string | null>(null);
  const selectedFlows = flows.filter((flow) => flow.src_ip === selected || flow.dst_ip === selected);
  const selectedAlerts = alerts.filter((alert) => alert.flow.src_ip === selected || alert.flow.dst_ip === selected);
  const protocols = rankedHosts(selectedFlows.map((flow) => flow.protocol));
  const risk = Math.max(0, ...selectedAlerts.map((alert) => alert.risk));
  const latest = selectedFlows.map((flow) => new Date(flow.timestamp_start).getTime()).sort((a, b) => b - a)[0];
  return <><div className="card-grid">{hosts.map((host) => <article className="host-card" key={host.host} tabIndex={0} onClick={() => setSelected(host.host)} onKeyDown={(event) => event.key === "Enter" && setSelected(host.host)}>
    <div className={`host-card__pulse ${host.alerting ? "is-alerting" : ""}`} />
    <h3 className="mono">{host.host}</h3>
    <dl><div><dt>Flows</dt><dd>{host.flows}</dd></div><div><dt>Destination fan-out</dt><dd>{host.destinations}</dd></div><div><dt>Peak risk</dt><dd>{Math.max(0, ...alerts.filter((alert) => alert.flow.src_ip === host.host || alert.flow.dst_ip === host.host).map((alert) => alert.risk)).toFixed(0)}</dd></div></dl>
    <Badge value={host.alerting ? "needs_review" : "benign"} />
  </article>)}</div>
  {selected && <aside className="drawer" aria-label="Host detail"><button className="drawer__close" onClick={() => setSelected(null)} aria-label="Close host detail">×</button><p className="eyebrow">Host activity ledger</p><h2 className="mono">{selected}</h2>
    <div className="signal-grid"><Metric label="Peak risk" value={risk.toFixed(0)} note={`${selectedAlerts.length} alerts`} /><Metric label="Recent activity" value={latest ? new Date(latest).toLocaleTimeString() : "none"} note={`${selectedFlows.length} flows loaded`} /><Metric label="Protocols" value={protocols.length} note="observed usage" /></div>
    <h3>Protocol usage</h3><div className="reason-list">{protocols.map((item) => <code key={item.label}>{item.label} · {item.count}</code>)}</div>
    <h3>Alert history</h3>{selectedAlerts.length ? <ol className="event-ledger">{selectedAlerts.map((alert) => <li key={alert.id}><div><strong>{alert.verdict.replaceAll("_", " ")}</strong><small>{new Date(alert.created_at).toLocaleString()} · {alert.detection.reason_codes.join(", ")}</small></div><span className={`risk risk--${alert.severity}`}>{alert.risk.toFixed(0)}</span></li>)}</ol> : <div className="state">No alert history in the loaded window.</div>}
  </aside>}</>;
}

function Models({ models, drift, alerts, status }: { models: ModelVersion[]; drift: DriftEvent[]; alerts: Alert[]; status?: SystemStatus }) {
  const scoreData = [0, 20, 40, 60, 80].map((floor) => ({ range: `${floor}–${floor + 19}`, detections: alerts.filter((alert) => alert.risk >= floor && alert.risk < floor + 20).length }));
  const loadErrors = status?.recent_health_events.filter((event) => event.service.includes("model") && event.status === "error") ?? [];
  return <><div className="split"><section className="panel"><header><span>Model registry</span><small>production pointer</small></header>
    {models.map((model) => <article className="registry-row" key={model.id}><div><strong>{model.model_name}</strong><small>v{model.version}</small></div><Badge value={model.production ? "benign" : "needs_review"} /></article>)}
    {models[0]?.metadata.known_limitations.map((item) => <p className="limitation" key={item}>{item}</p>)}
  </section><section className="panel"><header><span>Validation metrics</span><small>{models[0]?.metadata.feature_schema_version ?? "no schema"}</small></header>
    {models[0] ? <dl className="feature-ledger">{Object.entries(models[0].metadata.validation_metrics).slice(0, 10).map(([key, value]) => <div key={key}><dt>{key.replaceAll("_", " ")}</dt><dd>{typeof value === "number" ? value.toFixed(3) : String(value)}</dd></div>)}</dl> : <div className="state">No production metrics loaded.</div>}
  </section></div>
  <div className="overview-grid overview-grid--lower"><section className="panel"><header><span>Risk score distribution</span><small>loaded alerts</small></header><div className="chart chart--compact"><ResponsiveContainer width="100%" height="100%"><BarChart data={scoreData}><XAxis dataKey="range" stroke="#89a2ad" /><YAxis allowDecimals={false} stroke="#89a2ad" /><Tooltip cursor={{ fill: "#17313d" }} /><Bar dataKey="detections" fill="#e9b44c" isAnimationActive={false} /></BarChart></ResponsiveContainer></div></section>
    <section className="panel"><header><span>Drift events</span><small>never auto-retrains</small></header>{drift.length ? <ol className="event-ledger">{drift.map((event) => <li key={event.id}><div><strong>{event.signal.replaceAll("_", " ")}</strong><small>{new Date(event.detected_at).toLocaleString()}</small></div><span>{event.magnitude.toFixed(3)}</span></li>)}</ol> : <div className="state">No drift event has crossed a detector threshold.</div>}</section>
    <section className="panel"><header><span>Model loading errors</span><small>health ledger</small></header>{loadErrors.length ? loadErrors.map((event) => <p className="limitation" key={event.id}>{new Date(event.timestamp).toLocaleString()} · {event.status}</p>) : <div className="state">No model loading error is recorded.</div>}</section>
  </div></>;
}

function SystemHealth({ status, connected, flows }: { status?: SystemStatus; connected: boolean; flows: Flow[] }) {
  const health = status?.recent_health_events ?? [];
  return <><div className="metric-grid">
    <Metric label="Database" value={status?.database ?? "checking"} note="persistent store" />
    <Metric label="Detection queue" value={(status?.queue.lag ?? 0) + (status?.queue.pending ?? 0)} note={status?.queue.backpressure ? "capacity pressure" : "lag + pending"} />
    <Metric label="Throughput" value={`${(status?.throughput_per_second ?? observedFlowRate(flows)).toFixed(2)}/s`} note={status?.throughput_per_second === undefined ? "observed window" : "worker metric"} />
    <Metric label="WebSocket" value={connected ? "linked" : "reconnecting"} note="live alert stream" />
  </div><div className="overview-grid overview-grid--lower">
    <section className="panel ledger-panel"><header><span>Service readiness</span><small>reported only</small></header><dl><div><dt>Sensors</dt><dd>{status?.sensors ?? "not reported"}</dd></div><div><dt>Suricata</dt><dd>{status?.suricata_status ?? "not reported"}</dd></div><div><dt>Identity</dt><dd>{status?.auth_mode ?? "not reported"}</dd></div><div><dt>Governance</dt><dd>{status?.model_governance_enabled ? "enabled" : "read only"}</dd></div><div><dt>Loaded model</dt><dd>{status?.loaded_runtime_version ?? "not reported"}</dd></div><div><dt>Dropped records</dt><dd>{status?.dropped_records ?? "not reported"}</dd></div><div><dt>Worker latency</dt><dd>{status?.worker_latency_ms == null ? "not reported" : `${status.worker_latency_ms.toFixed(2)} ms`}</dd></div></dl></section>
    <section className="panel ledger-panel"><header><span>Retention</span><small>effective policy</small></header><dl><div><dt>Enabled</dt><dd>{status?.retention.enabled ? "yes" : "no"}</dd></div><div><dt>Operations</dt><dd>{status?.retention.days ? `${status.retention.days} days` : "external"}</dd></div><div><dt>Audit</dt><dd>{status?.retention.audit_days ? `${status.retention.audit_days} days` : "external"}</dd></div><div><dt>Interval</dt><dd>{status?.retention.interval_seconds ? `${status.retention.interval_seconds}s` : "not scheduled"}</dd></div><div><dt>Consumers</dt><dd>{status?.queue.consumers ?? 0}</dd></div></dl></section>
    <section className="panel"><header><span>Recent health events</span><small>bounded ledger</small></header>{health.length ? <ol className="event-ledger">{health.map((event) => <li key={event.id}><div><strong>{event.service}</strong><small>{new Date(event.timestamp).toLocaleString()}</small></div><Badge value={event.status === "error" ? "critical" : "benign"} /></li>)}</ol> : <div className="state">No health event has been recorded.</div>}</section>
  </div></>;
}

export function App() {
  const [view, setView] = useState<View>("overview");
  const [selected, setSelected] = useState<Alert | null>(null);
  const [paused, setPaused] = useState(false);
  const data = useOperationsData(paused);
  const alerts = data.alerts.data?.items ?? [];
  const incidents = data.incidents.data?.items ?? [];
  const flows = data.flows.data?.items ?? [];
  const hosts = data.hosts.data?.items ?? [];
  const models = data.models.data?.items ?? [];
  const drift = data.drift.data?.items ?? [];
  const loading = [data.alerts, data.incidents, data.flows, data.hosts, data.models].some((query) => query.isLoading);
  const error = [data.alerts, data.incidents, data.flows, data.hosts, data.models].find((query) => query.error)?.error ?? null;

  let content: React.ReactNode;
  if (view === "overview") content = <Overview alerts={alerts} incidents={incidents} flows={flows} models={models} status={data.status.data} drift={drift} />;
  else if (view === "alerts") content = <AlertTable alerts={alerts} onSelect={setSelected} paused={paused} setPaused={setPaused} />;
  else if (view === "incidents") content = <Incidents incidents={incidents} />;
  else if (view === "flows") content = <Flows flows={flows} />;
  else if (view === "hosts") content = <Hosts hosts={hosts} flows={flows} alerts={alerts} />;
  else if (view === "models") content = <Models models={models} drift={drift} alerts={alerts} status={data.status.data} />;
  else if (view === "system") content = <SystemHealth status={data.status.data} connected={data.connected} flows={flows} />;
  else content = null;

  return (
    <div className="shell">
      <aside className="sidebar">
        <a className="brand" href="#overview" onClick={() => setView("overview")}><span>A</span><div><strong>AegisFlow</strong><small>Network operations</small></div></a>
        <nav aria-label="Primary navigation">{views.map((item) => <button key={item.id} className={view === item.id ? "active" : ""} onClick={() => setView(item.id)}><span>{item.key}</span>{item.label}</button>)}</nav>
        <div className="sidebar__foot"><span className={`connection ${data.connected ? "is-live" : ""}`} />{data.connected ? "Live stream linked" : "Reconnecting stream"}</div>
      </aside>
      <main>
        {data.status.data?.mode === "demo" && <div className="demo-banner"><strong>Demo traffic</strong><span>Generated records are isolated and carry no real packet payloads.</span></div>}
        <header className="page-header"><div><p className="eyebrow">Operational surface / {views.find((item) => item.id === view)?.key}</p><h1>{views.find((item) => item.id === view)?.label}</h1></div><div className="clock"><span>UTC</span><strong>{new Date().toISOString().slice(11, 19)}</strong></div></header>
        <State loading={loading} error={error as Error | null} empty={false}>{content}</State>
      </main>
      {selected && <AlertDetail alert={selected} close={() => setSelected(null)} />}
    </div>
  );
}
