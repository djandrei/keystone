import { afterAll, afterEach, beforeAll, beforeEach, expect, it, vi } from "vitest";
import { render, screen, waitFor, act } from "@testing-library/react";
import { http, HttpResponse } from "msw";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { ToastProvider } from "@/components/ui/toast";
import { setAccess } from "@/auth/tokenStore";
import { server } from "@/tests/msw/server";
import { MockWebSocket } from "@/tests/mockWebSocket";
import { AnalysisPage } from "./AnalysisPage";

beforeAll(() => server.listen({ onUnhandledRequest: "error" }));
afterEach(() => {
  server.resetHandlers();
  vi.unstubAllGlobals();
});
afterAll(() => server.close());
beforeEach(() => {
  MockWebSocket.reset();
  vi.stubGlobal("WebSocket", MockWebSocket);
  setAccess("access-1");
});

function renderAt(id: number) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <ToastProvider>
      <QueryClientProvider client={qc}>
        <MemoryRouter initialEntries={[`/analyses/${id}`]}>
          <Routes>
            <Route path="/analyses/:id" element={<AnalysisPage />} />
          </Routes>
        </MemoryRouter>
      </QueryClientProvider>
    </ToastProvider>,
  );
}

it("renders streamed steps while running", async () => {
  server.use(
    http.get("/api/analyses/5", () =>
      HttpResponse.json({
        id: 5, team_id: 1, binary_id: 1, mode: "re", status: "running", model: "m",
        params: null, created_by: 1, created_at: null, started_at: null, finished_at: null,
        error: null, progress: { events: [] },
      }),
    ),
  );
  renderAt(5);
  await waitFor(() => expect(MockWebSocket.instances.length).toBe(1));
  act(() => {
    MockWebSocket.last().emit({ type: "step_start", step: "overview", seq: 1 });
    MockWebSocket.last().emit({ type: "step_finish", step: "overview", seq: 2, data: { imports: 2 } });
  });
  expect(await screen.findByText("overview")).toBeInTheDocument();
  expect(screen.getByText(/running/i)).toBeInTheDocument();
});

it("renders the RE report when succeeded", async () => {
  server.use(
    http.get("/api/analyses/9", () =>
      HttpResponse.json({
        id: 9, team_id: 1, binary_id: 1, mode: "re", status: "succeeded", model: "m",
        params: null, created_by: 1, created_at: null, started_at: null, finished_at: null,
        error: null, progress: { events: [{ type: "step_finish", step: "analyze", seq: 1 }] },
        re_result: {
          binary_type: "cli_tool", purpose: "lists files", key_functions: "main",
          attack_surface: "argv", language_runtime: "Go", tool_calls: 4,
        },
      }),
    ),
    http.get("/api/analyses/9/report", () => HttpResponse.text("# RE Analysis\nlanguage_runtime: Go")),
  );
  renderAt(9);
  expect(await screen.findByText("lists files")).toBeInTheDocument();
  expect(screen.getAllByText("Go").length).toBeGreaterThan(0);
  // no WS connection when not active
  expect(MockWebSocket.instances.length).toBe(0);
});
