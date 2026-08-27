import { afterAll, afterEach, beforeAll, expect, it } from "vitest";
import { render, screen } from "@testing-library/react";
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

it("lists recent analyses in the history table", async () => {
  localStorage.setItem(REFRESH_KEY, "refresh-1");
  server.use(
    refreshHandler(ADMIN),
    http.get("/api/analyses", () =>
      HttpResponse.json([
        { id: 42, team_id: 1, binary_id: 1, mode: "re", status: "succeeded", model: "m",
          params: null, created_by: 1, created_at: "2026-08-27T10:00:00", started_at: null,
          finished_at: null, error: null, progress: null },
      ]),
    ),
  );
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
  expect(await screen.findByText("#42")).toBeInTheDocument();
  expect(screen.getByText("succeeded")).toBeInTheDocument();
  expect(screen.getByRole("link", { name: /view/i })).toBeInTheDocument();
});
