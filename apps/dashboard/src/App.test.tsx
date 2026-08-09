// @vitest-environment jsdom

import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { cloneElement, isValidElement, type ReactElement } from "react";
import { afterEach, expect, test, vi } from "vitest";
import { App } from "./App";

vi.mock("recharts", async (importOriginal) => {
  const actual = await importOriginal<typeof import("recharts")>();
  return {
    ...actual,
    ResponsiveContainer: ({ children }: { children: ReactElement<{ width?: number; height?: number }> }) => (
      <div>{isValidElement(children) ? cloneElement(children, { width: 800, height: 300 }) : children}</div>
    )
  };
});

class MockSocket {
  onopen: (() => void) | null = null;
  onmessage: ((event: MessageEvent) => void) | null = null;
  onclose: (() => void) | null = null;
  constructor() { setTimeout(() => this.onopen?.(), 0); }
  close() {}
}

vi.stubGlobal("WebSocket", MockSocket);
afterEach(cleanup);
vi.stubGlobal(
  "ResizeObserver",
  class {
    observe() {}
    unobserve() {}
    disconnect() {}
  }
);
const incidentFixture = {
  id: "11111111-1111-4111-8111-111111111111",
  title: "Related authentication activity",
  status: "open",
  severity: "high",
  source_host: "10.0.0.8",
  source_hosts: ["10.0.0.8"],
  destination_hosts: ["10.0.0.9"],
  created_at: "2026-08-01T09:59:00Z",
  updated_at: "2026-08-01T10:00:00Z",
  alert_ids: ["alert-1"],
  alert_count: 1,
  acknowledged_alerts: 0,
  max_risk: 82,
  grouping_reasons: ["same source host", "time proximity"],
  reason_codes: ["REPEATED_AUTH_FAILURE"],
  signature_names: ["Repeated authentication pattern"],
  attack_stages: ["credential_access"],
  escalation_count: 0,
  timeline: [{
    alert_id: "alert-1",
    timestamp: "2026-08-01T10:00:00Z",
    verdict: "known_attack",
    severity: "high",
    risk: 82,
    attack_stage: "credential_access",
    source_host: "10.0.0.8",
    destination_host: "10.0.0.9",
    acknowledged: false
  }]
};
const alertFixture = {
  id: "22222222-2222-4222-8222-222222222222",
  created_at: "2026-08-01T10:00:00Z",
  verdict: "known_attack",
  severity: "high",
  risk: 82,
  acknowledged: false,
  flow: {
    event_id: "33333333-3333-4333-8333-333333333333",
    src_ip: "10.0.0.8",
    dst_ip: "10.0.0.9",
    src_port: 51000,
    dst_port: 22,
    protocol: "TCP",
    timestamp_start: "2026-08-01T09:59:59Z"
  },
  detection: {
    event_id: "44444444-4444-4444-8444-444444444444",
    verdict: "known_attack",
    severity: "high",
    final_risk_score: 82,
    reason_codes: ["REPEATED_AUTH_FAILURE"],
    explanation: "Known authentication pattern with model evidence.",
    anomaly_score: 0.42,
    reconstruction_error: 0.1,
    reconstruction_score: 0.2,
    known_attack_probability: 0.93,
    signature_score: 0.9,
    classifier_model_version: "0.2.0",
    feature_schema_version: "1.0.0"
  }
};
const flowFixture = {
  event_id: alertFixture.flow.event_id,
  timestamp_start: "2026-08-01T09:59:59Z",
  timestamp_end: "2026-08-01T10:00:00Z",
  src_ip: alertFixture.flow.src_ip,
  dst_ip: alertFixture.flow.dst_ip,
  src_port: alertFixture.flow.src_port,
  dst_port: alertFixture.flow.dst_port,
  protocol: "TCP",
  packets_forward: 10,
  packets_reverse: 8,
  bytes_forward: 1200,
  bytes_reverse: 900,
  duration_ms: 1000,
  packet_rate: 18,
  byte_rate: 2100,
  packet_length_mean: 116.7,
  packet_length_std: 12.4,
  iat_mean: 55.5,
  iat_std: 4.2,
  tcp_syn_count: 1,
  tcp_ack_count: 8,
  tcp_fin_count: 1,
  tcp_rst_count: 0,
  application_protocol: "ssh",
  direction: "outbound",
  source_adapter: "fixture",
  feature_extractor_version: "1.0.0",
  protocol_metadata: {},
  detection: alertFixture.detection,
  alert_id: alertFixture.id,
  signatures: [{
    signature_id: "9000001",
    signature_name: "Repeated authentication pattern",
    category: "credential access",
    severity: "high",
    source: "fixture"
  }]
};
vi.stubGlobal("fetch", vi.fn(async (input: string) => {
  const url = String(input);
  const isStatus = url.includes("/system/status");
  const isExplanation = url.includes("/explanation");
  const isIncidents = url.endsWith("/api/v1/incidents");
  const isIncidentDetail = url.includes(`/api/v1/incidents/${incidentFixture.id}`);
  const isAlerts = url.includes("/api/v1/alerts?");
  const isFlowDetail = url.endsWith(`/api/v1/flows/${flowFixture.event_id}`);
  const isFlows = url.includes("/api/v1/flows?");
  return {
    ok: true,
    json: async () => isStatus
      ? {
          database: "ready",
          sensors: 1,
          flows: 0,
          signature_events: 0,
          alerts: 0,
          incidents: 0,
          mode: "demo",
          queue: { pending: 0, lag: 0, consumers: 1 },
          retention: { enabled: true, days: 30, interval_seconds: 86400 },
          recent_health_events: []
        }
      : isExplanation
        ? {
            text: "AI advisory based on sanitized incident evidence.",
            provider: "openai-compatible",
            requested_provider: "openai-compatible",
            ai_generated: true,
            fallback: false,
            cached: false,
            incident_version_hash: "a".repeat(64),
            generated_at: "2026-08-01T10:00:00Z",
            limitations: ["Advisory only; cannot change detection."]
          }
        : isIncidents
          ? {
              items: [incidentFixture],
              count: 1
            }
          : isIncidentDetail
            ? incidentFixture
            : isAlerts
              ? { items: [alertFixture], count: 1, total: 1 }
              : isFlowDetail
                ? flowFixture
                : isFlows
                  ? { items: [flowFixture], count: 1, total: 1 }
                  : { items: [], count: 0 }
  };
}));

test("renders the operations dashboard and demo disclosure", async () => {
  render(<QueryClientProvider client={new QueryClient()}><App /></QueryClientProvider>);
  expect(screen.getByRole("heading", { name: "Overview" })).toBeTruthy();
  expect(await screen.findByText("Demo traffic")).toBeTruthy();
  fireEvent.click(screen.getByRole("button", { name: /System health/ }));
  expect(screen.getByText("Detection queue")).toBeTruthy();
});

test("loads incident explanations on demand and labels AI-generated text", async () => {
  render(<QueryClientProvider client={new QueryClient()}><App /></QueryClientProvider>);
  fireEvent.click(screen.getByRole("button", { name: /Incidents/ }));
  fireEvent.click(await screen.findByRole("button", { name: "Open incident" }));
  expect(await screen.findAllByText("credential access")).toHaveLength(2);
  expect(await screen.findByText("ai generated")).toBeTruthy();
  expect(screen.getByText("AI advisory based on sanitized incident evidence.")).toBeTruthy();
  expect(screen.getByText("openai-compatible")).toBeTruthy();
  fireEvent.change(screen.getByLabelText("Add analyst note"), {
    target: { value: "Review authentication sequence" }
  });
  fireEvent.click(screen.getByRole("button", { name: "Add note" }));
  expect(await screen.findByText("Analyst note added.")).toBeTruthy();
});

test("filters, pauses, and acknowledges a live alert", async () => {
  render(<QueryClientProvider client={new QueryClient()}><App /></QueryClientProvider>);
  fireEvent.click(screen.getByRole("button", { name: /Live alerts/ }));
  fireEvent.click(await screen.findByRole("button", { name: "Pause live feed" }));
  expect(screen.getByRole("button", { name: "Resume live feed" })).toBeTruthy();
  fireEvent.change(screen.getByRole("combobox", { name: "Severity" }), { target: { value: "high" } });
  fireEvent.click(await screen.findByText("10.0.0.8 → 10.0.0.9:22"));
  expect(await screen.findByText("Known authentication pattern with model evidence.")).toBeTruthy();
  fireEvent.click(screen.getByRole("button", { name: "Acknowledge alert" }));
  expect(await screen.findByRole("button", { name: "Acknowledged" })).toBeTruthy();
});

test("selects a flow for sanitized export and opens associated evidence", async () => {
  render(<QueryClientProvider client={new QueryClient()}><App /></QueryClientProvider>);
  fireEvent.click(screen.getByRole("button", { name: /Flow explorer/ }));
  const checkbox = await screen.findByRole("checkbox", { name: `Select flow ${flowFixture.event_id}` });
  fireEvent.click(checkbox);
  const exportLink = screen.getByRole("link", { name: "Export selected (1)" });
  expect(exportLink.getAttribute("href")).toContain(flowFixture.event_id);
  fireEvent.click(screen.getByText("10.0.0.9:22"));
  expect(await screen.findByRole("dialog", { name: "Flow evidence" })).toBeTruthy();
  expect(await screen.findByText("Repeated authentication pattern · credential access")).toBeTruthy();
});
