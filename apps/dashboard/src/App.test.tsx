// @vitest-environment jsdom

import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen } from "@testing-library/react";
import { cloneElement, isValidElement, type ReactElement } from "react";
import { expect, test, vi } from "vitest";
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
  return {
    ok: true,
    json: async () => isStatus
      ? { database: "ready", sensors: 1, flows: 0, alerts: 0, incidents: 0, mode: "demo" }
      : { items: [], count: 0 }
  };
}));

test("renders the operations dashboard and demo disclosure", async () => {
  render(<QueryClientProvider client={new QueryClient()}><App /></QueryClientProvider>);
  expect(screen.getByRole("heading", { name: "Overview" })).toBeTruthy();
  expect(await screen.findByText("Demo traffic")).toBeTruthy();
});
