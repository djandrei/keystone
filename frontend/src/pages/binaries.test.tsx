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
