import { useEffect, useMemo, useState } from "react";
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
import { alertSocketUrl, api } from "./api";
import type { Alert, Flow, Host, Incident, ModelVersion } from "./types";

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

function useOperationsData() {
  const queryClient = useQueryClient();
  const alerts = useQuery({ queryKey: ["alerts"], queryFn: () => api.alerts() });
  const incidents = useQuery({ queryKey: ["incidents"], queryFn: api.incidents });
  const flows = useQuery({ queryKey: ["flows"], queryFn: api.flows });
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
      socket = new WebSocket(alertSocketUrl());
      socket.onopen = () => setConnected(true);
      socket.onmessage = (event) => {
        const payload = JSON.parse(event.data) as { type: string; items: Alert[] };
        if (payload.type === "alerts") {
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
  status
}: {
  alerts: Alert[];
  incidents: Incident[];
  flows: Flow[];
  models: ModelVersion[];
  status?: { sensors: number; mode: string };
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
  return (
    <>
      <Flowline alerts={alerts} />
      <div className="metric-grid">
        <Metric label="Observed flows" value={flows.length} note="validated records" />
        <Metric label="Open incidents" value={incidents.filter((i) => i.status !== "closed").length} note="deterministic grouping" />
        <Metric label="Unknown-behaviour flags" value={unknown} note="statistical, not confirmed" />
        <Metric label="Sensors ready" value={status?.sensors ?? "—"} note={`${status?.mode ?? "unknown"} mode`} />
      </div>
      <div className="split">
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
    </>
  );
}

function AlertTable({
  alerts,
  onSelect
}: {
  alerts: Alert[];
  onSelect: (alert: Alert) => void;
}) {
  return (
    <div className="table-wrap">
      <table>
        <thead><tr><th>Time</th><th>Verdict</th><th>Risk</th><th>Route</th><th>Protocol</th></tr></thead>
        <tbody>
          {alerts.map((alert) => (
            <tr key={alert.id} onClick={() => onSelect(alert)} tabIndex={0} onKeyDown={(event) => event.key === "Enter" && onSelect(alert)}>
              <td>{new Date(alert.created_at).toLocaleTimeString()}</td>
              <td><Badge value={alert.verdict} /></td>
              <td><span className={`risk risk--${alert.severity}`}>{alert.risk.toFixed(0)}</span></td>
              <td className="mono">{alert.flow.src_ip} → {alert.flow.dst_ip}:{alert.flow.dst_port}</td>
              <td>{alert.flow.protocol}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function AlertDetail({ alert, close }: { alert: Alert; close: () => void }) {
  const [disposition, setDisposition] = useState("requires_investigation");
  const [comment, setComment] = useState("");
  const mutation = useMutation({
    mutationFn: () => api.feedback(alert.id, { actor: "demo-analyst", disposition, comment })
  });
  return (
    <aside className="drawer" aria-label="Alert detail">
      <button className="drawer__close" onClick={close} aria-label="Close alert detail">×</button>
      <p className="eyebrow">Detection evidence</p>
      <h2>{alert.verdict.replaceAll("_", " ")}</h2>
      <div className="risk-orbit"><span>{alert.risk.toFixed(0)}</span><small>risk / 100</small></div>
      <p>{alert.detection.explanation}</p>
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
  const shown = flows.filter((flow) =>
    `${flow.src_ip} ${flow.dst_ip} ${flow.protocol} ${flow.dst_port}`.toLowerCase().includes(filter.toLowerCase())
  );
  return <>
    <label className="search">Filter endpoints, protocol, or port
      <input value={filter} onChange={(event) => setFilter(event.target.value)} placeholder="10.20.0.15 or TCP" />
    </label>
    <div className="table-wrap"><table><thead><tr><th>Started</th><th>Source</th><th>Destination</th><th>Packets</th><th>Bytes out / in</th></tr></thead>
      <tbody>{shown.map((flow) => <tr key={flow.event_id}><td>{new Date(flow.timestamp_start).toLocaleTimeString()}</td><td className="mono">{flow.src_ip}:{flow.src_port}</td><td className="mono">{flow.dst_ip}:{flow.dst_port}</td><td>{flow.packets_forward + flow.packets_reverse}</td><td>{flow.bytes_forward.toLocaleString()} / {flow.bytes_reverse.toLocaleString()}</td></tr>)}</tbody>
    </table></div>
  </>;
}

function Hosts({ hosts }: { hosts: Host[] }) {
  return <div className="card-grid">{hosts.map((host) => <article className="host-card" key={host.host}>
    <div className={`host-card__pulse ${host.alerting ? "is-alerting" : ""}`} />
    <h3 className="mono">{host.host}</h3>
    <dl><div><dt>Flows</dt><dd>{host.flows}</dd></div><div><dt>Destination fan-out</dt><dd>{host.destinations}</dd></div></dl>
    <Badge value={host.alerting ? "needs_review" : "benign"} />
  </article>)}</div>;
}

function Models({ models, drift }: { models: ModelVersion[]; drift: Record<string, unknown>[] }) {
  return <div className="split"><section className="panel"><header><span>Model registry</span><small>production pointer</small></header>
    {models.map((model) => <article className="registry-row" key={model.id}><div><strong>{model.model_name}</strong><small>v{model.version}</small></div><Badge value={model.production ? "benign" : "needs_review"} /></article>)}
    {models[0]?.metadata.known_limitations.map((item) => <p className="limitation" key={item}>{item}</p>)}
  </section><section className="panel"><header><span>Drift events</span><small>never auto-retrains</small></header>
    {drift.length ? drift.map((event, index) => <pre key={index}>{JSON.stringify(event, null, 2)}</pre>) : <div className="state">No drift event has crossed a detector threshold.</div>}
  </section></div>;
}

export function App() {
  const [view, setView] = useState<View>("overview");
  const [selected, setSelected] = useState<Alert | null>(null);
  const data = useOperationsData();
  const alerts = data.alerts.data?.items ?? [];
  const incidents = data.incidents.data?.items ?? [];
  const flows = data.flows.data?.items ?? [];
  const hosts = data.hosts.data?.items ?? [];
  const models = data.models.data?.items ?? [];
  const drift = data.drift.data?.items ?? [];
  const loading = [data.alerts, data.incidents, data.flows, data.hosts, data.models].some((query) => query.isLoading);
  const error = [data.alerts, data.incidents, data.flows, data.hosts, data.models].find((query) => query.error)?.error ?? null;

  let content: React.ReactNode;
  if (view === "overview") content = <Overview alerts={alerts} incidents={incidents} flows={flows} models={models} status={data.status.data} />;
  else if (view === "alerts") content = <AlertTable alerts={alerts} onSelect={setSelected} />;
  else if (view === "incidents") content = <Incidents incidents={incidents} />;
  else if (view === "flows") content = <Flows flows={flows} />;
  else if (view === "hosts") content = <Hosts hosts={hosts} />;
  else if (view === "models") content = <Models models={models} drift={drift} />;
  else if (view === "system") content = (
    <div className="metric-grid">
      <Metric label="Database" value={data.status.data?.database ?? "checking"} note="persistent store" />
      <Metric
        label="Detection queue"
        value={(data.status.data?.queue?.lag ?? 0) + (data.status.data?.queue?.pending ?? 0)}
        note="lag + pending"
      />
      <Metric label="Flows" value={data.status.data?.flows ?? "—"} note="stored" />
      <Metric label="WebSocket" value={data.connected ? "linked" : "reconnecting"} note="live alert stream" />
    </div>
  );
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
