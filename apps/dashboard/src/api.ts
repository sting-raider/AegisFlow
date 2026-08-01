import type {
  Alert,
  DriftEvent,
  Flow,
  FlowDetail,
  Host,
  Incident,
  IncidentExplanation,
  ModelVersion,
  Page,
  SystemStatus
} from "./types";

const API = import.meta.env.VITE_API_URL ?? "";

async function get<T>(path: string): Promise<T> {
  const response = await fetch(`${API}${path}`);
  if (!response.ok) throw new Error(`${response.status} ${response.statusText}`);
  return response.json() as Promise<T>;
}

export const api = {
  alerts: (query = "") => get<Page<Alert>>(`/api/v1/alerts${query}`),
  alert: (id: string) => get<Alert>(`/api/v1/alerts/${id}`),
  incidents: () => get<Page<Incident>>("/api/v1/incidents"),
  incident: (id: string) => get<Incident>(`/api/v1/incidents/${id}`),
  incidentExplanation: (id: string) =>
    get<IncidentExplanation>(`/api/v1/incidents/${id}/explanation`),
  setIncidentStatus: async (id: string, status: string) => {
    const response = await fetch(`${API}/api/v1/incidents/${id}/status`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ status })
    });
    if (!response.ok) throw new Error("Incident status could not be updated");
    return response.json() as Promise<{ id: string; status: string }>;
  },
  addIncidentNote: async (id: string, note: string, actor = "demo-analyst") => {
    const response = await fetch(`${API}/api/v1/incidents/${id}/notes`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ actor, note })
    });
    if (!response.ok) throw new Error("Incident note could not be recorded");
    return response.json() as Promise<{ id: string; actor: string; note: string; timestamp: string }>;
  },
  acknowledge: async (id: string, actor = "demo-analyst") => {
    const response = await fetch(`${API}/api/v1/alerts/${id}/acknowledge`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ actor })
    });
    if (!response.ok) throw new Error("Alert could not be acknowledged");
    return response.json() as Promise<{ id: string; acknowledged: boolean; actor: string }>;
  },
  flows: (query = "") => get<Page<Flow>>(`/api/v1/flows${query}`),
  flow: (id: string) => get<FlowDetail>(`/api/v1/flows/${id}`),
  hosts: () => get<Page<Host>>("/api/v1/hosts"),
  models: () => get<Page<ModelVersion>>("/api/v1/models"),
  drift: () => get<Page<DriftEvent>>("/api/v1/drift-events"),
  status: () => get<SystemStatus>("/api/v1/system/status"),
  feedback: async (
    id: string,
    body: { actor: string; disposition: string; comment: string }
  ) => {
    const response = await fetch(`${API}/api/v1/alerts/${id}/feedback`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body)
    });
    if (!response.ok) throw new Error("Feedback could not be recorded");
    return response.json() as Promise<Record<string, unknown>>;
  }
};

export function flowExportUrl(eventIds: string[]): string {
  const parameters = new URLSearchParams();
  eventIds.forEach((id) => parameters.append("event_id", id));
  const query = parameters.toString();
  return `${API}/api/v1/exports/flows.csv${query ? `?${query}` : ""}`;
}

export function alertSocketUrl(): string {
  const configured = import.meta.env.VITE_WS_URL as string | undefined;
  if (configured) return configured;
  const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
  const host = window.location.port === "5173" ? "127.0.0.1:8000" : window.location.host;
  return `${protocol}//${host}/api/v1/stream/alerts`;
}
