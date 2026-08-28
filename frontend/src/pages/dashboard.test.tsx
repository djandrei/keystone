import { afterAll, afterEach, beforeAll, expect, it } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { http, HttpResponse } from "msw";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import { App } from "@/App";
import { AuthProvider } from "@/auth/AuthContext";
import { ToastProvider } from "@/components/ui/toast";
import { clearTokens, REFRESH_KEY } from "@/auth/tokenStore";
import { server } from "@/tests/msw/server";
import { ADMIN, refreshHandler } from "@/tests/msw/auth";

beforeAll(() => server.listen({ onUnhandledRequest: "error" }));
afterEach(() => {
  server.resetHandlers();
  clearTokens();
  localStorage.clear();
});
afterAll(() => server.close());

function analysis(id: number, team: number, who: string) {
  return {
    id, team_id: team, binary_id: 1, mode: "re", status: "succeeded", model: "m",
    params: null, created_by: 1, created_by_username: who, created_at: "2026-08-27T10:00:00",
    started_at: null, finished_at: null, error: null, progress: null,
    binary_filename: "crackme2.x86_64",
    summary: { kind: "re", purpose: "A CLI string-comparison tool" },
  };
}

function renderApp() {
  localStorage.setItem(REFRESH_KEY, "refresh-1");
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <QueryClientProvider client={qc}>
      <ToastProvider>
        <AuthProvider>
          <MemoryRouter initialEntries={["/"]}>
            <App />
          </MemoryRouter>
        </AuthProvider>
      </ToastProvider>
    </QueryClientProvider>,
  );
}

it("lists recent analyses with the analyst who ran them", async () => {
  server.use(
    refreshHandler(ADMIN),
    http.get("/api/teams", () => HttpResponse.json([{ id: 1, name: "Blue", created_at: null, created_by: 1 }])),
    http.get("/api/analyses", () =>
      HttpResponse.json({ items: [analysis(42, 1, "neo")], total: 1, limit: 50, offset: 0 })),
  );
  renderApp();
  // the run, the analyst who ran it, and the Task description (binary + a brief
  // outcome) are all listed — asserted together in waitFor so the settle after
  // the active team loads (which re-runs the query) doesn't race the checks
  await waitFor(() => {
    const t = document.body.textContent ?? "";
    expect(t).toContain("neo");
    expect(t).toContain("crackme2.x86_64");
    expect(t).toContain("A CLI string-comparison tool");
  });
});

it("scopes the dashboard to the active team and switches it", async () => {
  server.use(
    refreshHandler(ADMIN),
    http.get("/api/teams", () =>
      HttpResponse.json([
        { id: 1, name: "Blue", created_at: null, created_by: 1 },
        { id: 2, name: "Red", created_at: null, created_by: 1 },
      ]),
    ),
    http.get("/api/analyses", ({ request }) => {
      const team = new URL(request.url).searchParams.get("team_id");
      const rows = team === "2" ? [analysis(99, 2, "bob")] : [analysis(42, 1, "neo")];
      return HttpResponse.json({ items: rows, total: rows.length, limit: 50, offset: 0 });
    }),
  );
  renderApp();
  // defaults to the first team (Blue) -> neo's run
  await waitFor(() => expect(document.body.textContent).toContain("neo"));

  // switch to Red -> bob's run replaces it
  await userEvent.click(await screen.findByLabelText("Active team"));
  await userEvent.click(await screen.findByRole("option", { name: "Red" }));
  await waitFor(() => expect(document.body.textContent).toContain("bob"));
  expect(document.body.textContent).not.toContain("neo");
});
