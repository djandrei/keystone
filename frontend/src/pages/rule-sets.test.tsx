import { afterAll, afterEach, beforeAll, expect, it, vi } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { http, HttpResponse } from "msw";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import { ToastProvider } from "@/components/ui/toast";
import { setAccess } from "@/auth/tokenStore";
import { server } from "@/tests/msw/server";
import { RuleSetsPage } from "./RuleSetsPage";

const role = { current: "analyst" as "admin" | "analyst" | "viewer" };
vi.mock("@/auth/AuthContext", () => ({
  useAuth: () => ({ user: { id: 1, username: "neo", email: "n@x", role: role.current } }),
  useCurrentUser: () => ({ id: 1, username: "neo", email: "n@x", role: role.current }),
}));
vi.mock("@/team/TeamContext", () => ({
  useTeam: () => ({ teams: [], activeTeamId: 1, setActiveTeamId: () => {} }),
}));

beforeAll(() => server.listen({ onUnhandledRequest: "error" }));
afterEach(() => {
  server.resetHandlers();
  role.current = "analyst";
});
afterAll(() => server.close());

function version(over: Record<string, unknown> = {}) {
  return {
    id: 30,
    version_no: 1,
    content_sha256: "x",
    rule_ids: ["dangerous-copy"],
    rule_count: 1,
    notes: null,
    security: null,
    created_by: 1,
    created_at: "2026-08-31T00:00:00+00:00",
    ...over,
  };
}

const BUILTIN = {
  id: 3,
  team_id: null,
  name: "Decompiled C — VR defaults",
  description: "Ships with Keystone",
  languages: ["c"],
  is_builtin: true,
  archived: false,
  created_by: null,
  created_at: null,
  latest_version: version(),
};

const TEAM_RS = {
  id: 7,
  team_id: 1,
  name: "firmware rules",
  description: null,
  languages: ["c"],
  is_builtin: false,
  archived: false,
  created_by: 1,
  created_at: null,
  latest_version: version({ id: 70, version_no: 2, rule_count: 3 }),
};

const TEAMS = [{ id: 1, name: "Blue", created_at: null, created_by: 1 }];

function renderPage() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <ToastProvider>
      <QueryClientProvider client={qc}>
        <MemoryRouter>
          <RuleSetsPage />
        </MemoryRouter>
      </QueryClientProvider>
    </ToastProvider>,
  );
}

function baseHandlers() {
  return [
    http.get("/api/teams", () => HttpResponse.json(TEAMS)),
    http.get("/api/rule-sets", () => HttpResponse.json([BUILTIN, TEAM_RS])),
  ];
}

it("lists built-ins and team rule sets in separate sections", async () => {
  setAccess("access-1");
  server.use(...baseHandlers());
  renderPage();

  expect(await screen.findByText("Decompiled C — VR defaults")).toBeInTheDocument();
  expect(screen.getByText("firmware rules")).toBeInTheDocument();
  expect(screen.getByText("Built-in")).toBeInTheDocument();
  expect(screen.getByText("v2")).toBeInTheDocument();
});

it("an analyst gets View (not Edit) on a built-in, but can clone it", async () => {
  setAccess("access-1");
  let cloned: { team_id: number } | null = null;
  server.use(
    ...baseHandlers(),
    http.post("/api/rule-sets/3/clone", async ({ request }) => {
      cloned = (await request.json()) as { team_id: number };
      return HttpResponse.json({ ...TEAM_RS, name: "Decompiled C — VR defaults (copy)" }, { status: 201 });
    }),
  );
  renderPage();

  await screen.findByText("Decompiled C — VR defaults");
  // the built-in row offers View; the team row offers Edit
  expect(screen.getByText("View")).toBeInTheDocument();
  expect(screen.getByText("Edit")).toBeInTheDocument();

  await userEvent.click(screen.getAllByText("Clone")[0]);
  await waitFor(() => expect(cloned).toEqual({ team_id: 1, name: "Decompiled C — VR defaults (copy)" }));
});

it("an admin may edit a built-in directly", async () => {
  setAccess("access-1");
  role.current = "admin";
  server.use(...baseHandlers());
  renderPage();
  await screen.findByText("Decompiled C — VR defaults");
  expect(screen.queryByText("View")).not.toBeInTheDocument();
  expect(screen.getAllByText("Edit")).toHaveLength(2);
});

it("a viewer sees the library but no write controls", async () => {
  setAccess("access-1");
  role.current = "viewer";
  server.use(...baseHandlers());
  renderPage();
  await screen.findByText("firmware rules");
  expect(screen.queryByText("New rule set")).not.toBeInTheDocument();
  expect(screen.queryByText("Clone")).not.toBeInTheDocument();
  expect(screen.queryByText("Archive")).not.toBeInTheDocument();
});

it("creates a rule set from the editor", async () => {
  setAccess("access-1");
  let posted: Record<string, unknown> | null = null;
  server.use(
    ...baseHandlers(),
    http.post("/api/rule-sets", async ({ request }) => {
      posted = (await request.json()) as Record<string, unknown>;
      return HttpResponse.json(TEAM_RS, { status: 201 });
    }),
  );
  renderPage();

  await userEvent.click(await screen.findByText("New rule set"));
  await userEvent.type(screen.getByLabelText("Name"), "my rules");
  await userEvent.click(screen.getByText("Create"));

  await waitFor(() => expect(posted).not.toBeNull());
  expect(posted!.name).toBe("my rules");
  expect(String(posted!.content)).toContain("rules:");
  expect(posted!.team_id).toBe(1);
});

it("renders validation errors instead of saving", async () => {
  setAccess("access-1");
  server.use(
    ...baseHandlers(),
    http.post("/api/rule-sets/validate", () =>
      HttpResponse.json({ ok: false, errors: ["`rules:` must be a non-empty list"] }),
    ),
  );
  renderPage();

  await userEvent.click(await screen.findByText("New rule set"));
  await userEvent.click(screen.getByText("Validate"));
  expect(await screen.findByText("`rules:` must be a non-empty list")).toBeInTheDocument();
});

it("warns when a rule message looks like prompt injection", async () => {
  setAccess("access-1");
  server.use(
    ...baseHandlers(),
    http.post("/api/rule-sets/validate", () =>
      HttpResponse.json({
        ok: true,
        errors: [],
        rule_ids: ["sneaky"],
        security: { suspected: true, evidence: ["ignore previous"] },
      }),
    ),
  );
  renderPage();

  await userEvent.click(await screen.findByText("New rule set"));
  await userEvent.click(screen.getByText("Validate"));
  expect(await screen.findByText(/looks like prompt injection/)).toBeInTheDocument();
});

it("saving an existing rule set appends a version rather than rewriting it", async () => {
  setAccess("access-1");
  let body: Record<string, unknown> | null = null;
  server.use(
    ...baseHandlers(),
    http.get("/api/rule-sets/7", () =>
      HttpResponse.json({ ...TEAM_RS, versions: [version({ version_no: 2 }), version()], content: "rules: []" }),
    ),
    http.post("/api/rule-sets/7/versions", async ({ request }) => {
      body = (await request.json()) as Record<string, unknown>;
      return HttpResponse.json(version({ version_no: 3 }), { status: 201 });
    }),
  );
  renderPage();

  await userEvent.click(await screen.findByText("Edit"));
  const notes = await screen.findByLabelText("What changed?");
  // every past version is on show — the point of never rewriting one
  expect(screen.getByText(/Version history \(2\)/)).toBeInTheDocument();

  await userEvent.type(notes, "tightened the copy rule");
  await userEvent.click(screen.getByText("Save new version"));

  await waitFor(() => expect(body).not.toBeNull());
  expect(body!.notes).toBe("tightened the copy rule");
});

it("archives a rule set", async () => {
  setAccess("access-1");
  let patched: Record<string, unknown> | null = null;
  server.use(
    ...baseHandlers(),
    http.patch("/api/rule-sets/7", async ({ request }) => {
      patched = (await request.json()) as Record<string, unknown>;
      return HttpResponse.json({ ...TEAM_RS, archived: true });
    }),
  );
  renderPage();

  await userEvent.click(await screen.findByText("Archive"));
  await waitFor(() => expect(patched).toEqual({ archived: true }));
});
