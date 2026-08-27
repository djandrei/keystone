import { afterAll, afterEach, beforeAll, expect, it } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { http, HttpResponse } from "msw";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { setAccess } from "@/auth/tokenStore";
import { server } from "@/tests/msw/server";
import { AuditPage } from "./AuditPage";

beforeAll(() => server.listen({ onUnhandledRequest: "error" }));
afterEach(() => server.resetHandlers());
afterAll(() => server.close());

const ROWS = [
  { id: 2, user_id: 1, username: "admin", action: "team.create", target_type: "team", target_id: "5",
    detail: { name: "Red Cell" }, created_at: "2026-08-27T10:05:00" },
  { id: 1, user_id: 1, username: "admin", action: "user.create", target_type: "user", target_id: "9",
    detail: { username: "neo" }, created_at: "2026-08-27T10:00:00" },
];

function renderPage() {
  setAccess("access-1");
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={qc}>
      <AuditPage />
    </QueryClientProvider>,
  );
}

it("lists audit rows and filters by action; drawer shows detail", async () => {
  server.use(
    http.get("/api/audit", ({ request }) => {
      const action = new URL(request.url).searchParams.get("action");
      const items = action ? ROWS.filter((r) => r.action.includes(action)) : ROWS;
      return HttpResponse.json({ items, total: items.length, limit: 50, offset: 0 });
    }),
  );
  renderPage();
  await waitFor(() => expect(document.body.textContent).toContain("team.create"));
  expect(document.body.textContent).toContain("user.create");

  // filter
  await userEvent.type(screen.getByLabelText(/filter by action/i), "team");
  await waitFor(() => expect(document.body.textContent).not.toContain("user.create"));
  expect(document.body.textContent).toContain("team.create");

  // detail drawer
  await userEvent.click(screen.getAllByRole("button", { name: /view/i })[0]);
  expect(await screen.findByRole("dialog")).toHaveTextContent("Red Cell");
});
