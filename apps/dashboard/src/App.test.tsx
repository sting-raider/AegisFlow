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
vi.stubGlobal("fetch", vi.fn(async (input: string) => {
  const isStatus = input.includes("/system/status");
  const isExplanation = input.includes("/explanation");
  const isIncidents = input.endsWith("/api/v1/incidents");
  return {
    ok: true,
    json: async () => isStatus
      ? {
          database: "ready",
          sensors: 1,
          flows: 0,
          alerts: 0,
          incidents: 0,
          mode: "demo",
          queue: { pending: 0, lag: 0, consumers: 1 }
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
              items: [{
                id: "11111111-1111-4111-8111-111111111111",
                title: "Related authentication activity",
                status: "open",
                severity: "high",
                source_host: "10.0.0.8",
                created_at: "2026-08-01T09:59:00Z",
                updated_at: "2026-08-01T10:00:00Z",
                alert_ids: ["alert-1"],
                grouping_reasons: ["same source host"]
              }],
              count: 1
            }
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
  fireEvent.click(await screen.findByRole("button", { name: "Explain incident" }));
  expect(await screen.findByText("ai generated")).toBeTruthy();
  expect(screen.getByText("AI advisory based on sanitized incident evidence.")).toBeTruthy();
  expect(screen.getByText("openai-compatible")).toBeTruthy();
});
