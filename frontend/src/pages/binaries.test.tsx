import { afterAll, afterEach, beforeAll, expect, it, vi } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { http, HttpResponse } from "msw";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { ToastProvider } from "@/components/ui/toast";
import { setAccess } from "@/auth/tokenStore";
import { server } from "@/tests/msw/server";
import { api } from "@/lib/api";
import { binariesApi } from "@/lib/analysisApi";
import { BinariesPage } from "./BinariesPage";

// SharedWithCard reads the current user; the page isn't wrapped in AuthProvider here
vi.mock("@/auth/AuthContext", () => ({
  useCurrentUser: () => ({ id: 1, username: "neo", email: "neo@x", role: "admin" }),
}));

beforeAll(() => server.listen({ onUnhandledRequest: "error" }));
afterEach(() => server.resetHandlers());
afterAll(() => server.close());

const BINARY = {
  id: 1, team_id: 1, project_id: 9, project_name: "Unassigned", sha256: "a".repeat(64),
  filename: "ls", size: 16120, format: "ELF", arch: "x86-64", platform: "linux",
  ghidra_program_name: "ls", uploaded_by: 1, created_at: null,
};

// The Run VR picker reads the deployment default and the library.
const SETTINGS = {
  llm_endpoint_url: null, default_model: null, triage_model: null, triage_endpoint_url: null,
  default_rule_set_id: 3, updated_by: null, updated_at: null,
  llm_key_configured: false, triage_key_configured: false,
};

const RULE_SETS = [
  {
    id: 3, team_id: null, name: "Decompiled C — VR defaults", description: null, languages: ["c"],
    is_builtin: true,
    attribution: { author: "Marco Ivaldi (raptor)", license: "MIT", url: "https://github.com/0xdea/semgrep-rules", commit: "33155497b25b4639193db016962af2df46290b10" }, archived: false, created_by: null, created_at: null,
    latest_version: {
      id: 30, version_no: 1, content_sha256: "x", rule_ids: ["dangerous-copy"], rule_count: 1,
      notes: null, security: null, created_by: null, created_at: null,
    },
  },
];

const PROJECTS = [
  { id: 9, team_id: 1, name: "Unassigned", is_default: true, binary_count: 1, created_by: 1, created_at: null },
];

const TEAM_DETAIL = {
  id: 1, name: "Blue", created_at: null, created_by: 1,
  members: [
    { user_id: 1, username: "neo", team_role: "lead", added_at: null },
    { user_id: 2, username: "trinity", team_role: "member", added_at: null },
  ],
};

const PROJECTS_TWO = [
  { id: 5, team_id: 1, name: "firmware-x", is_default: false, binary_count: 0, created_by: 1, created_at: null },
  { id: 9, team_id: 1, name: "Unassigned", is_default: true, binary_count: 0, created_by: 1, created_at: null },
];

it("uploads a binary as multipart FormData (team_id + file)", async () => {
  // axios+FormData+MSW hangs in jsdom, so assert the request the client builds.
  const post = vi.spyOn(api, "post").mockResolvedValue({ data: BINARY });
  const file = new File([new Uint8Array([0x7f, 0x45, 0x4c, 0x46])], "ls");
  const result = await binariesApi.upload(1, file);
  expect(result.filename).toBe("ls");
  expect(post).toHaveBeenCalledWith("/binaries", expect.any(FormData));
  const form = post.mock.calls[0][1] as FormData;
  expect(form.get("team_id")).toBe("1");
  expect(form.get("file")).toBeInstanceOf(File);
  post.mockRestore();
});

function renderPage() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <ToastProvider>
      <QueryClientProvider client={qc}>
        <MemoryRouter initialEntries={["/binaries"]}>
          <Routes>
            <Route path="/binaries" element={<BinariesPage />} />
            <Route path="/analyses/:id" element={<div>analysis view 77</div>} />
          </Routes>
        </MemoryRouter>
      </QueryClientProvider>
    </ToastProvider>,
  );
}

it("lists binaries and starts an RE analysis from Run RE", async () => {
  setAccess("access-1");
  let started: { binaryId: number } | null = null;
  server.use(
    http.get("/api/teams", () => HttpResponse.json([{ id: 1, name: "Blue", created_at: null, created_by: 1 }])),
    http.get("/api/teams/:id", () => HttpResponse.json(TEAM_DETAIL)),
    http.get("/api/projects", () => HttpResponse.json(PROJECTS)),
    http.get("/api/settings", () => HttpResponse.json(SETTINGS)),
    http.get("/api/rule-sets", () => HttpResponse.json(RULE_SETS)),
    http.get("/api/binaries", () => HttpResponse.json([BINARY])),
    http.post("/api/binaries/1/analyses", () => {
      started = { binaryId: 1 };
      return HttpResponse.json({
        id: 77, team_id: 1, binary_id: 1, mode: "re", status: "queued", model: "m",
        params: null, created_by: 1, created_at: null, started_at: null, finished_at: null,
        error: null, progress: null,
      }, { status: 201 });
    }),
  );
  renderPage();
  // the seeded binary is listed, with its human-readable size
  expect(await screen.findByRole("cell", { name: "ls" })).toBeInTheDocument();
  expect(screen.getByRole("cell", { name: "15.7 KB" })).toBeInTheDocument();
  await userEvent.click(screen.getByRole("button", { name: /run re/i }));
  // starts the analysis and navigates to its view
  await waitFor(() => expect(started).toEqual({ binaryId: 1 }));
  expect(await screen.findByText("analysis view 77")).toBeInTheDocument();
});

it("surfaces the team members the projects are shared with", async () => {
  setAccess("access-1");
  server.use(
    http.get("/api/teams", () => HttpResponse.json([{ id: 1, name: "Blue", created_at: null, created_by: 1 }])),
    http.get("/api/teams/:id", () => HttpResponse.json(TEAM_DETAIL)),
    http.get("/api/projects", () => HttpResponse.json(PROJECTS)),
    http.get("/api/settings", () => HttpResponse.json(SETTINGS)),
    http.get("/api/rule-sets", () => HttpResponse.json(RULE_SETS)),
    http.get("/api/binaries", () => HttpResponse.json([BINARY])),
  );
  renderPage();
  // the "Shared with" panel lists both members and the count
  expect(await screen.findByText(/shared with 2 members of blue/i)).toBeInTheDocument();
  expect(screen.getByText("neo")).toBeInTheDocument();
  expect(screen.getByText("trinity")).toBeInTheDocument();
  // and each project section shows the shared-with hint
  expect(screen.getByText(/· shared with 2 members/)).toBeInTheDocument();
});

it("groups binaries into per-project sections", async () => {
  setAccess("access-1");
  server.use(
    http.get("/api/teams", () => HttpResponse.json([{ id: 1, name: "Blue", created_at: null, created_by: 1 }])),
    http.get("/api/teams/:id", () => HttpResponse.json(TEAM_DETAIL)),
    http.get("/api/projects", () => HttpResponse.json([
      { id: 5, team_id: 1, name: "firmware-x", is_default: false, binary_count: 1, created_by: 1, created_at: null },
      { id: 9, team_id: 1, name: "Unassigned", is_default: true, binary_count: 1, created_by: 1, created_at: null },
    ])),
    http.get("/api/settings", () => HttpResponse.json(SETTINGS)),
    http.get("/api/rule-sets", () => HttpResponse.json(RULE_SETS)),
    http.get("/api/binaries", () => HttpResponse.json([
      { ...BINARY, id: 1, filename: "fw.bin", project_id: 5, project_name: "firmware-x" },
      { ...BINARY, id: 2, filename: "ls", project_id: 9, project_name: "Unassigned" },
    ])),
  );
  renderPage();
  // a section per project, each with its binary
  expect(await screen.findByRole("button", { name: /toggle firmware-x/i })).toBeInTheDocument();
  expect(screen.getByRole("button", { name: /toggle unassigned/i })).toBeInTheDocument();
  expect(screen.getByRole("cell", { name: "fw.bin" })).toBeInTheDocument();
  expect(screen.getByRole("cell", { name: "ls" })).toBeInTheDocument();
});

it("creates a project", async () => {
  setAccess("access-1");
  let created: unknown = null;
  server.use(
    http.get("/api/teams", () => HttpResponse.json([{ id: 1, name: "Blue", created_at: null, created_by: 1 }])),
    http.get("/api/teams/:id", () => HttpResponse.json(TEAM_DETAIL)),
    http.get("/api/projects", () => HttpResponse.json(PROJECTS)),
    http.get("/api/settings", () => HttpResponse.json(SETTINGS)),
    http.get("/api/rule-sets", () => HttpResponse.json(RULE_SETS)),
    http.get("/api/binaries", () => HttpResponse.json([])),
    http.post("/api/projects", async ({ request }) => {
      created = await request.json();
      return HttpResponse.json({ id: 5, team_id: 1, name: "firmware-x", is_default: false, binary_count: 0, created_by: 1, created_at: null }, { status: 201 });
    }),
  );
  renderPage();
  const input = await screen.findByLabelText("New project");
  await userEvent.type(input, "firmware-x");
  await userEvent.click(screen.getByRole("button", { name: /create/i }));
  await waitFor(() => expect(created).toMatchObject({ team_id: 1, name: "firmware-x" }));
});

it("deletes an empty project", async () => {
  setAccess("access-1");
  let deleted: string | null = null;
  server.use(
    http.get("/api/teams", () => HttpResponse.json([{ id: 1, name: "Blue", created_at: null, created_by: 1 }])),
    http.get("/api/teams/:id", () => HttpResponse.json(TEAM_DETAIL)),
    http.get("/api/projects", () => HttpResponse.json(PROJECTS_TWO)),
    http.get("/api/settings", () => HttpResponse.json(SETTINGS)),
    http.get("/api/rule-sets", () => HttpResponse.json(RULE_SETS)),
    http.get("/api/binaries", () => HttpResponse.json([])),
    http.delete("/api/projects/5", () => { deleted = "5"; return new HttpResponse(null, { status: 204 }); }),
  );
  renderPage();
  await userEvent.click(await screen.findByRole("button", { name: /delete firmware-x/i }));
  await waitFor(() => expect(deleted).toBe("5"));
});

it("surfaces 'move them out first' when deleting a non-empty project", async () => {
  setAccess("access-1");
  server.use(
    http.get("/api/teams", () => HttpResponse.json([{ id: 1, name: "Blue", created_at: null, created_by: 1 }])),
    http.get("/api/teams/:id", () => HttpResponse.json(TEAM_DETAIL)),
    http.get("/api/projects", () => HttpResponse.json(PROJECTS_TWO)),
    http.get("/api/settings", () => HttpResponse.json(SETTINGS)),
    http.get("/api/rule-sets", () => HttpResponse.json(RULE_SETS)),
    http.get("/api/binaries", () => HttpResponse.json([])),
    http.delete("/api/projects/5", () => HttpResponse.json({ error: "has_binaries", binaries: 2 }, { status: 409 })),
  );
  renderPage();
  await userEvent.click(await screen.findByRole("button", { name: /delete firmware-x/i }));
  expect(await screen.findByText(/move them out first/i)).toBeInTheDocument();
});

it("renames a project", async () => {
  setAccess("access-1");
  let renamed: { name?: string } | null = null;
  server.use(
    http.get("/api/teams", () => HttpResponse.json([{ id: 1, name: "Blue", created_at: null, created_by: 1 }])),
    http.get("/api/teams/:id", () => HttpResponse.json(TEAM_DETAIL)),
    http.get("/api/projects", () => HttpResponse.json(PROJECTS_TWO)),
    http.get("/api/settings", () => HttpResponse.json(SETTINGS)),
    http.get("/api/rule-sets", () => HttpResponse.json(RULE_SETS)),
    http.get("/api/binaries", () => HttpResponse.json([])),
    http.patch("/api/projects/5", async ({ request }) => {
      renamed = (await request.json()) as { name?: string };
      return HttpResponse.json({ id: 5, team_id: 1, name: "fw-y", is_default: false, binary_count: 0, created_by: 1, created_at: null });
    }),
  );
  renderPage();
  await userEvent.click(await screen.findByRole("button", { name: /rename firmware-x/i }));
  const input = await screen.findByDisplayValue("firmware-x");
  await userEvent.clear(input);
  await userEvent.type(input, "fw-y{Enter}");
  await waitFor(() => expect(renamed).toMatchObject({ name: "fw-y" }));
});

// --------------------------------------------------------------------------- //
// Run VR now asks which rule sets to scan with, before the analysis starts.
// --------------------------------------------------------------------------- //
const RULE_SETS_TWO = [
  RULE_SETS[0],
  {
    id: 7, team_id: 1, name: "firmware rules", description: null, languages: ["c"],
    is_builtin: false, attribution: null, archived: false, created_by: 1, created_at: null,
    latest_version: {
      id: 70, version_no: 2, content_sha256: "y", rule_ids: ["a", "b"], rule_count: 2,
      notes: null, security: null, created_by: 1, created_at: null,
    },
  },
];

function vrHandlers(onStart: (body: Record<string, unknown>) => void, ruleSets = RULE_SETS_TWO) {
  return [
    http.get("/api/teams", () => HttpResponse.json([{ id: 1, name: "Blue", created_at: null, created_by: 1 }])),
    http.get("/api/teams/:id", () => HttpResponse.json(TEAM_DETAIL)),
    http.get("/api/projects", () => HttpResponse.json(PROJECTS)),
    http.get("/api/settings", () => HttpResponse.json(SETTINGS)),
    http.get("/api/rule-sets", () => HttpResponse.json(ruleSets)),
    http.get("/api/binaries", () => HttpResponse.json([BINARY])),
    http.post("/api/binaries/1/analyses", async ({ request }) => {
      onStart((await request.json()) as Record<string, unknown>);
      return HttpResponse.json({ id: 77, mode: "vr", status: "queued" }, { status: 201 });
    }),
  ];
}

it("Run VR opens the rule-set picker instead of starting immediately", async () => {
  setAccess("access-1");
  let started: Record<string, unknown> | null = null;
  server.use(...vrHandlers((b) => (started = b)));
  renderPage();

  await userEvent.click(await screen.findByText("Run VR"));
  expect(await screen.findByText("Run VR analysis")).toBeInTheDocument();
  expect(started).toBeNull(); // nothing started yet — the analyst has to choose

  await userEvent.click(screen.getByText("Start analysis"));
  await waitFor(() => expect(started).not.toBeNull());
});

it("preselects the deployment default rule set", async () => {
  setAccess("access-1");
  let started: Record<string, unknown> | null = null;
  server.use(...vrHandlers((b) => (started = b)));
  renderPage();

  await userEvent.click(await screen.findByText("Run VR"));
  // SETTINGS.default_rule_set_id === 3, the built-in
  const builtin = await screen.findByLabelText("Decompiled C — VR defaults");
  expect(builtin).toBeChecked();
  expect(screen.getByLabelText("firmware rules")).not.toBeChecked();

  await userEvent.click(screen.getByText("Start analysis"));
  await waitFor(() => expect(started).not.toBeNull());
  expect((started as unknown as { params: { rule_set_ids: number[] } }).params.rule_set_ids).toEqual([3]);
});

it("sends every selected rule set, and the rule-class pause flag", async () => {
  setAccess("access-1");
  let started: Record<string, unknown> | null = null;
  server.use(...vrHandlers((b) => (started = b)));
  renderPage();

  await userEvent.click(await screen.findByText("Run VR"));
  await userEvent.click(await screen.findByLabelText("firmware rules"));
  await userEvent.click(screen.getByText("Start analysis"));

  await waitFor(() => expect(started).not.toBeNull());
  const params = (started as unknown as { params: { rule_set_ids: number[]; interactive: boolean } }).params;
  expect(params.rule_set_ids).toEqual([3, 7]);
  expect(params.interactive).toBe(true);
});

it("the rule-class pause can be turned off before starting", async () => {
  setAccess("access-1");
  let started: Record<string, unknown> | null = null;
  server.use(...vrHandlers((b) => (started = b)));
  renderPage();

  await userEvent.click(await screen.findByText("Run VR"));
  await userEvent.click(await screen.findByLabelText("Let me choose which finding class to triage"));
  await userEvent.click(screen.getByText("Start analysis"));

  await waitFor(() => expect(started).not.toBeNull());
  expect((started as unknown as { params: { interactive: boolean } }).params.interactive).toBe(false);
});

it("cancelling the picker starts nothing", async () => {
  setAccess("access-1");
  let started: Record<string, unknown> | null = null;
  server.use(...vrHandlers((b) => (started = b)));
  renderPage();

  await userEvent.click(await screen.findByText("Run VR"));
  await userEvent.click(await screen.findByText("Cancel"));
  await waitFor(() => expect(screen.queryByText("Run VR analysis")).not.toBeInTheDocument());
  expect(started).toBeNull();
});

it("cannot start with nothing selected", async () => {
  setAccess("access-1");
  server.use(...vrHandlers(() => {}, []));
  renderPage();

  await userEvent.click(await screen.findByText("Run VR"));
  expect(await screen.findByText(/No rule sets available/)).toBeInTheDocument();
  expect(screen.getByText("Start analysis")).toBeDisabled();
});

it("credits the rule author in the Run VR picker", async () => {
  setAccess("access-1");
  server.use(...vrHandlers(() => {}));
  renderPage();

  await userEvent.click(await screen.findByText("Run VR"));
  await screen.findByLabelText("Decompiled C — VR defaults");
  // the built-in fixture carries a credit; the team one does not
  expect(screen.getByText("Marco Ivaldi (raptor)")).toBeInTheDocument();
  expect(screen.getAllByText(/Rules by/)).toHaveLength(1);
});

it("the pre-scan checkbox says who picks the class, not whether to narrow", async () => {
  setAccess("access-1");
  let started: Record<string, unknown> | null = null;
  server.use(...vrHandlers((b) => (started = b)));
  // nothing should start while the analyst is still reading the options
  renderPage();

  await userEvent.click(await screen.findByText("Run VR"));
  const box = await screen.findByLabelText("Let me choose which finding class to triage");
  expect(box).toBeChecked();
  expect(screen.getByText(/pause after the scan/i)).toBeInTheDocument();
  // and it is honest that the scan narrows either way
  expect(screen.getByText(/other findings are counted but not triaged/i)).toBeInTheDocument();

  await userEvent.click(box);
  expect(screen.getByText(/highest-severity class is triaged automatically/i)).toBeInTheDocument();
  expect(started).toBeNull();
});
