import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { http, HttpResponse } from "msw";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import { App } from "@/App";
import { AuthProvider } from "@/auth/AuthContext";
import { ToastProvider } from "@/components/ui/toast";
import { api } from "@/lib/api";
import { clearTokens, REFRESH_KEY, setAccess } from "@/auth/tokenStore";
import { server } from "@/tests/msw/server";
import { ADMIN, VIEWER, loginHandler, logoutHandler, refreshHandler } from "@/tests/msw/auth";

beforeAll(() => server.listen({ onUnhandledRequest: "error" }));
afterEach(() => {
  server.resetHandlers();
  clearTokens();
  localStorage.clear();
});
afterAll(() => server.close());
beforeEach(() => server.use(http.get("/api/analyses", () => HttpResponse.json({ items: [], total: 0, limit: 50, offset: 0 }))));

function renderApp(initial = "/") {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={qc}>
      <ToastProvider>
        <AuthProvider>
          <MemoryRouter initialEntries={[initial]}>
            <App />
          </MemoryRouter>
        </AuthProvider>
      </ToastProvider>
    </QueryClientProvider>,
  );
}

describe("auth routing", () => {
  it("redirects an unauthenticated visitor to the login page", async () => {
    renderApp("/");
    expect(await screen.findByRole("button", { name: /sign in/i })).toBeInTheDocument();
  });

  it("logs in and lands on the dashboard", async () => {
    server.use(loginHandler());
    renderApp("/");
    await screen.findByRole("button", { name: /sign in/i });
    await userEvent.type(screen.getByLabelText(/username/i), "admin");
    await userEvent.type(screen.getByLabelText(/password/i), "secret");
    await userEvent.click(screen.getByRole("button", { name: /sign in/i }));
    expect(await screen.findByText(/welcome back, admin/i)).toBeInTheDocument();
  });

  it("shows an error on bad credentials", async () => {
    server.use(loginHandler());
    renderApp("/login");
    await userEvent.type(screen.getByLabelText(/username/i), "admin");
    await userEvent.type(screen.getByLabelText(/password/i), "wrong");
    await userEvent.click(screen.getByRole("button", { name: /sign in/i }));
    expect(await screen.findByRole("alert")).toHaveTextContent(/invalid username or password/i);
  });

  it("validates required fields without calling the API", async () => {
    renderApp("/login");
    await userEvent.click(screen.getByRole("button", { name: /sign in/i }));
    expect(await screen.findByText(/username is required/i)).toBeInTheDocument();
    expect(screen.getByText(/password is required/i)).toBeInTheDocument();
  });

  it("restores a session from a stored refresh token", async () => {
    localStorage.setItem(REFRESH_KEY, "refresh-1");
    server.use(refreshHandler(ADMIN));
    renderApp("/");
    expect(await screen.findByText(/welcome back, admin/i)).toBeInTheDocument();
  });

  it("silently refreshes on a 401 and retries the request", async () => {
    // A stale access token with a valid refresh token: the first call 401s,
    // the interceptor refreshes to access-2, then the retry succeeds.
    setAccess("stale");
    localStorage.setItem(REFRESH_KEY, "refresh-1");
    server.use(refreshHandler(ADMIN));
    let calls = 0;
    server.use(
      http.get("/api/ping", ({ request }) => {
        calls += 1;
        if (request.headers.get("Authorization") !== "Bearer access-2") {
          return HttpResponse.json({ error: "unauthorized" }, { status: 401 });
        }
        return HttpResponse.json({ pong: true });
      }),
    );
    const res = await api.get("/ping");
    expect(res.data).toEqual({ pong: true });
    expect(calls).toBe(2); // first 401, retried after refresh
  });

  it("hides admin-only routes from a viewer (redirects to dashboard)", async () => {
    localStorage.setItem(REFRESH_KEY, "refresh-1");
    server.use(refreshHandler(VIEWER));
    renderApp("/admin/users");
    expect(await screen.findByText(/welcome back, vic/i)).toBeInTheDocument();
    expect(screen.queryByText(/user management/i)).not.toBeInTheDocument();
  });

  it("logout clears the session and returns to login", async () => {
    localStorage.setItem(REFRESH_KEY, "refresh-1");
    server.use(refreshHandler(ADMIN), logoutHandler());
    renderApp("/");
    await screen.findByText(/welcome back, admin/i);
    await userEvent.click(screen.getByRole("button", { name: /account menu/i }));
    await userEvent.click(await screen.findByRole("menuitem", { name: /sign out/i }));
    await waitFor(() => expect(screen.getByRole("button", { name: /sign in/i })).toBeInTheDocument());
    expect(localStorage.getItem(REFRESH_KEY)).toBeNull();
  });
});
