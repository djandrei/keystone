import { afterAll, afterEach, beforeAll, beforeEach, expect, it, vi } from "vitest";
import { render, screen, waitFor, act } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
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

it("renders VR findings when a VR analysis succeeds", async () => {
  server.use(
    http.get("/api/analyses/11", () =>
      HttpResponse.json({
        id: 11, team_id: 1, binary_id: 1, mode: "vr", status: "succeeded", model: "m",
        params: { rule: "integer-overflow" }, created_by: 1, created_at: null, started_at: null,
        finished_at: null, error: null,
        progress: { events: [{ type: "step_finish", step: "reachability", seq: 1 }] },
      }),
    ),
    http.get("/api/analyses/11/report", () => HttpResponse.text("# VR Analysis")),
    http.get("/api/analyses/11/findings", () =>
      HttpResponse.json([
        { id: 1, rule: "integer-overflow", file: "parse.c", line: 3, semgrep_message: "overflow",
          classification: "true_positive", risk_level: "high", cwe_id: "CWE-190",
          reasoning: "unchecked", reachable: "yes", entry_path: "ioctl", confidence: "high" },
      ]),
    ),
  );
  renderAt(11);
  expect(await screen.findByText("CWE-190")).toBeInTheDocument();
  expect(screen.getByText(/vulnerability findings/i)).toBeInTheDocument();
});

it("shows the rule picker on needs_input and selects a rule", async () => {
  let picked: string | null = null;
  server.use(
    http.get("/api/analyses/12", () =>
      HttpResponse.json({
        id: 12, team_id: 1, binary_id: 1, mode: "vr", status: "running", model: "m",
        params: null, created_by: 1, created_at: null, started_at: null, finished_at: null, error: null,
        progress: { events: [{ type: "needs_input", step: "rule_pick", data: { classes: { "integer-overflow": 2, "format-string": 1 } } }] },
      }),
    ),
    http.post("/api/analyses/12/select-rule", async ({ request }) => {
      picked = ((await request.json()) as { rule: string }).rule;
      return HttpResponse.json({ status: "ok", rule: picked });
    }),
  );
  renderAt(12);
  await userEvent.click(await screen.findByRole("button", { name: /integer-overflow/ }));
  await waitFor(() => expect(picked).toBe("integer-overflow"));
});

it("names the exact rule set versions the scan ran", async () => {
  server.use(
    http.get("/api/analyses/14", () =>
      HttpResponse.json({
        id: 14, team_id: 1, binary_id: 1, mode: "vr", status: "succeeded", model: "m",
        params: { rule: "dangerous-copy" }, created_by: 1, created_at: null, started_at: null,
        finished_at: null, error: null, progress: { events: [] },
        rule_sets: [
          { rule_set_id: 3, rule_set_version_id: 30, name: "Decompiled C", version_no: 1, is_builtin: true, rule_count: 4 },
          { rule_set_id: 7, rule_set_version_id: 71, name: "firmware rules", version_no: 2, is_builtin: false, rule_count: 3 },
        ],
      }),
    ),
    http.get("/api/analyses/14/report", () => HttpResponse.text("# VR Analysis")),
    http.get("/api/analyses/14/findings", () => HttpResponse.json([])),
  );
  renderAt(14);
  expect(await screen.findByText("Rule sets:")).toBeInTheDocument();
  // the pinned version number, not just the name — that's what keeps the report
  // explainable after the rule set moves on
  expect(screen.getByText("v1")).toBeInTheDocument();
  expect(screen.getByText("v2")).toBeInTheDocument();
  expect(screen.getByText(/firmware rules/)).toBeInTheDocument();
});

it("shows no rule-set line on an analysis that pinned none", async () => {
  server.use(
    http.get("/api/analyses/15", () =>
      HttpResponse.json({
        id: 15, team_id: 1, binary_id: 1, mode: "re", status: "queued", model: null,
        params: null, created_by: 1, created_at: null, started_at: null, finished_at: null,
        error: null, progress: { events: [] }, rule_sets: [],
      }),
    ),
  );
  renderAt(15);
  await screen.findByText(/Analysis #15/);
  expect(screen.queryByText("Rule sets:")).not.toBeInTheDocument();
});
