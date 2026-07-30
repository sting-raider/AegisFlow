import type {
  Alert,
  Flow,
  Host,
  Incident,
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
  flows: () => get<Page<Flow>>("/api/v1/flows"),
  hosts: () => get<Page<Host>>("/api/v1/hosts"),
  models: () => get<Page<ModelVersion>>("/api/v1/models"),
  drift: () => get<Page<Record<string, unknown>>>("/api/v1/drift-events"),
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

export function alertSocketUrl(): string {
  const configured = import.meta.env.VITE_WS_URL as string | undefined;
  if (configured) return configured;
  const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
  const host = window.location.port === "5173" ? "127.0.0.1:8000" : window.location.host;
  return `${protocol}//${host}/api/v1/stream/alerts`;
}
