import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { http, HttpResponse } from "msw";
import { QueryClientProvider } from "@tanstack/react-query";
import { QueryClient } from "@tanstack/react-query";
import { ToastProvider } from "@/components/ui/toast";
import { setAccess } from "@/auth/tokenStore";
import { server } from "@/tests/msw/server";
import { UsersAdminPage } from "./UsersAdminPage";
import { TeamsAdminPage } from "./TeamsAdminPage";
import { SettingsPage } from "./SettingsPage";

beforeAll(() => server.listen({ onUnhandledRequest: "error" }));
afterEach(() => server.resetHandlers());
afterAll(() => server.close());

function renderPage(ui: React.ReactElement) {
  setAccess("access-1"); // requests carry a bearer
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <ToastProvider>
      <QueryClientProvider client={qc}>{ui}</QueryClientProvider>
    </ToastProvider>,
  );
}

describe("UsersAdminPage", () => {
  it("lists users and creates a new one", async () => {
    const users = [
      { id: 1, username: "admin", email: "a@x", role: "admin", is_active: true, created_at: null, last_login_at: null },
    ];
    server.use(
      http.get("/api/users", () => HttpResponse.json(users)),
      http.post("/api/users", async ({ request }) => {
        const body = (await request.json()) as { username: string };
        const created = {
          id: 2,
          username: body.username,
          email: "neo@x",
          role: "analyst",
          is_active: true,
          created_at: null,
          last_login_at: null,
          temp_password: "tmp-secret",
        };
        users.push(created);
        return HttpResponse.json(created, { status: 201 });
      }),
    );
    renderPage(<UsersAdminPage />);
    expect(await screen.findByText("a@x")).toBeInTheDocument();

    await userEvent.click(screen.getByRole("button", { name: /new user/i }));
    const dialog = await screen.findByRole("dialog");
    await userEvent.type(within(dialog).getByLabelText(/username/i), "neo");
    await userEvent.type(within(dialog).getByLabelText(/email/i), "neo@x.io");
    await userEvent.click(within(dialog).getByRole("button", { name: /create user/i }));

    // temp password surfaced + list refetched to include the new user
    expect(await screen.findByText(/temporary password: tmp-secret/i)).toBeInTheDocument();
    expect(await screen.findByText("neo")).toBeInTheDocument();
  });
});

describe("TeamsAdminPage", () => {
  it("adds a member to a team", async () => {
    const detail = {
      id: 5,
      name: "Blue",
      created_at: null,
      created_by: 1,
      members: [] as { user_id: number; username: string; team_role: string; added_at: null }[],
    };
    server.use(
      http.get("/api/teams", () => HttpResponse.json([{ id: 5, name: "Blue", created_at: null, created_by: 1 }])),
      http.get("/api/teams/5", () => HttpResponse.json(detail)),
      http.get("/api/users", () =>
        HttpResponse.json([
          { id: 9, username: "carol", email: "c@x", role: "analyst", is_active: true, created_at: null, last_login_at: null },
        ]),
      ),
      http.post("/api/teams/5/members", async ({ request }) => {
        const body = (await request.json()) as { user_id: number };
        detail.members.push({ user_id: body.user_id, username: "carol", team_role: "member", added_at: null });
        return HttpResponse.json({ status: "ok" }, { status: 201 });
      }),
    );
    renderPage(<TeamsAdminPage />);
    await userEvent.click(await screen.findByRole("button", { name: /manage members/i }));

    const dialog = await screen.findByRole("dialog");
    await userEvent.click(within(dialog).getByLabelText(/add member/i));
    await userEvent.click(await screen.findByRole("option", { name: "carol" }));
    await userEvent.click(within(dialog).getByRole("button", { name: /^add$/i }));

    expect(await within(dialog).findByText("carol")).toBeInTheDocument();
  });
});

describe("SettingsPage", () => {
  it("loads and saves settings", async () => {
    let saved: Record<string, unknown> | null = null;
    server.use(
      http.get("/api/settings", () =>
        HttpResponse.json({
          llm_endpoint_url: null,
          default_model: null,
          semgrep_config: null,
          updated_by: null,
          updated_at: null,
          llm_key_configured: true,
        }),
      ),
      http.put("/api/settings", async ({ request }) => {
        saved = (await request.json()) as Record<string, unknown>;
        return HttpResponse.json({ ...saved, updated_by: 1, updated_at: null, llm_key_configured: true });
      }),
    );
    renderPage(<SettingsPage />);
    const model = await screen.findByLabelText(/default model/i);
    await userEvent.type(screen.getByLabelText(/llm endpoint url/i), "https://llm.example/api");
    await userEvent.type(model, "qwen/qwen3-8b");
    await userEvent.click(screen.getByRole("button", { name: /save settings/i }));

    await waitFor(() => expect(saved).toMatchObject({ default_model: "qwen/qwen3-8b" }));
    expect(await screen.findByText(/settings saved/i)).toBeInTheDocument();
  });

  it("tests the connection and reports the result", async () => {
    server.use(
      http.get("/api/settings", () =>
        HttpResponse.json({
          llm_endpoint_url: "https://llm.example/api",
          default_model: "m1",
          semgrep_config: null,
          updated_by: 1,
          updated_at: null,
          llm_key_configured: true,
        }),
      ),
      http.post("/api/settings/test-connection", () => HttpResponse.json({ ok: true, models: ["m1", "m2"] })),
    );
    renderPage(<SettingsPage />);
    await userEvent.click(await screen.findByRole("button", { name: /test connection/i }));
    expect(await screen.findByRole("status")).toHaveTextContent(/connected — 2 models/i);
  });
});
