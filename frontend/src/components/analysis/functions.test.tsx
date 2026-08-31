import { afterAll, afterEach, beforeAll, expect, it, vi } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { http, HttpResponse } from "msw";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { ToastProvider } from "@/components/ui/toast";
import { setAccess } from "@/auth/tokenStore";
import { server } from "@/tests/msw/server";
import { FunctionsPanel } from "./FunctionsPanel";

const role = { current: "analyst" as "admin" | "analyst" | "viewer" };
vi.mock("@/auth/AuthContext", () => ({
  useAuth: () => ({ user: { id: 1, username: "neo", email: "n@x", role: role.current } }),
  useCurrentUser: () => ({ id: 1, username: "neo", email: "n@x", role: role.current }),
}));

beforeAll(() => server.listen({ onUnhandledRequest: "error" }));
afterEach(() => {
  server.resetHandlers();
  role.current = "analyst";
});
afterAll(() => server.close());

const ROWS = [
  {
    id: 1, address: "401146", original_name: "FUN_401146",
    suggested_name: "parse_ioctl_header", display_name: "parse_ioctl_header",
    purpose: "Reads the IOCTL code and input length.", source: "llm", included: true,
  },
  {
    id: 2, address: "401200", original_name: "FUN_401200",
    suggested_name: null, display_name: "FUN_401200",
    purpose: null, source: "llm", included: true,
  },
  {
    id: 3, address: "401300", original_name: "FUN_401300",
    suggested_name: "hand_named", display_name: "hand_named",
    purpose: null, source: "user", included: false,
  },
];

function renderPanel() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <ToastProvider>
      <QueryClientProvider client={qc}>
        <FunctionsPanel analysisId={77} />
      </QueryClientProvider>
    </ToastProvider>,
  );
}

it("lists functions with the Ghidra symbol always visible", async () => {
  setAccess("access-1");
  server.use(http.get("/api/analyses/77/functions", () => HttpResponse.json(ROWS)));
  renderPanel();

  expect(await screen.findByText("parse_ioctl_header")).toBeInTheDocument();
  // the identity travels with the friendly name — not behind a hover
  expect(screen.getByText("FUN_401146 @ 401146")).toBeInTheDocument();
  expect(screen.getByText("Reads the IOCTL code and input length.")).toBeInTheDocument();
});

it("shows the raw symbol when the model produced nothing usable", async () => {
  setAccess("access-1");
  server.use(http.get("/api/analyses/77/functions", () => HttpResponse.json(ROWS)));
  renderPanel();
  await screen.findByText("parse_ioctl_header");
  expect(screen.getByText("FUN_401200 @ 401200")).toBeInTheDocument();
});

it("marks a hand-edited name", async () => {
  setAccess("access-1");
  server.use(http.get("/api/analyses/77/functions", () => HttpResponse.json(ROWS)));
  renderPanel();
  expect(await screen.findByText("edited")).toBeInTheDocument();
});

it("unticking excludes the function from the report", async () => {
  setAccess("access-1");
  let body: Record<string, unknown> | null = null;
  server.use(
    http.get("/api/analyses/77/functions", () => HttpResponse.json(ROWS)),
    http.patch("/api/analyses/77/functions", async ({ request }) => {
      body = (await request.json()) as Record<string, unknown>;
      return HttpResponse.json(ROWS.map((r) => (r.id === 1 ? { ...r, included: false } : r)));
    }),
  );
  renderPanel();

  const box = await screen.findByLabelText("Include parse_ioctl_header in the report");
  expect(box).toBeChecked();
  await userEvent.click(box);
  await waitFor(() => expect(body).toEqual({ exclude: [1] }));
});

it("ticking an excluded function includes it again", async () => {
  setAccess("access-1");
  let body: Record<string, unknown> | null = null;
  server.use(
    http.get("/api/analyses/77/functions", () => HttpResponse.json(ROWS)),
    http.patch("/api/analyses/77/functions", async ({ request }) => {
      body = (await request.json()) as Record<string, unknown>;
      return HttpResponse.json(ROWS);
    }),
  );
  renderPanel();
  await userEvent.click(await screen.findByLabelText("Include hand_named in the report"));
  await waitFor(() => expect(body).toEqual({ include: [3] }));
});

it("renames a function by hand", async () => {
  setAccess("access-1");
  let body: Record<string, unknown> | null = null;
  server.use(
    http.get("/api/analyses/77/functions", () => HttpResponse.json(ROWS)),
    http.patch("/api/function-names/2", async ({ request }) => {
      body = (await request.json()) as Record<string, unknown>;
      return HttpResponse.json({ ...ROWS[1], suggested_name: "check_key", source: "user" });
    }),
  );
  renderPanel();

  await userEvent.click(await screen.findByLabelText("Rename FUN_401200"));
  const input = await screen.findByLabelText("New name for FUN_401200");
  await userEvent.type(input, "check_key");
  await userEvent.click(screen.getByLabelText("Save name for FUN_401200"));
  await waitFor(() => expect(body).toEqual({ suggested_name: "check_key" }));
});

it("surfaces a rejected name instead of failing silently", async () => {
  setAccess("access-1");
  server.use(
    http.get("/api/analyses/77/functions", () => HttpResponse.json(ROWS)),
    http.patch("/api/function-names/1", () =>
      HttpResponse.json({ error: "invalid_name" }, { status: 400 }),
    ),
  );
  renderPanel();
  await userEvent.click(await screen.findByLabelText("Rename FUN_401146"));
  await userEvent.click(screen.getByLabelText("Save name for FUN_401146"));
  expect(await screen.findByText(/plain identifier/)).toBeInTheDocument();
});

it("a viewer sees the list but no controls", async () => {
  setAccess("access-1");
  role.current = "viewer";
  server.use(http.get("/api/analyses/77/functions", () => HttpResponse.json(ROWS)));
  renderPanel();
  await screen.findByText("parse_ioctl_header");
  expect(screen.getByLabelText("Include parse_ioctl_header in the report")).toBeDisabled();
  expect(screen.queryByLabelText("Rename FUN_401146")).not.toBeInTheDocument();
});

it("renders nothing when the analysis named no functions", async () => {
  setAccess("access-1");
  server.use(http.get("/api/analyses/77/functions", () => HttpResponse.json([])));
  const { container } = (() => {
    renderPanel();
    return { container: document.body };
  })();
  await waitFor(() => expect(container.textContent).not.toContain("Functions ("));
});
