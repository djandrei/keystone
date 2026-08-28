import { describe, expect, it, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";

vi.mock("@/auth/AuthContext", () => ({
  useCurrentUser: () => ({ id: 2, username: "trinity", email: "t@x", role: "analyst" }),
}));
vi.mock("@/lib/adminApi", () => ({
  teamsApi: {
    get: vi.fn(async () => ({
      id: 1, name: "Blue", created_at: null, created_by: 1,
      members: [
        { user_id: 1, username: "neo", team_role: "lead", added_at: null },
        { user_id: 2, username: "trinity", team_role: "member", added_at: null },
      ],
    })),
  },
}));

import { SharedWithCard } from "./SharedWithCard";

function renderCard() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <QueryClientProvider client={qc}>
      <MemoryRouter>
        <SharedWithCard teamId={1} />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

describe("SharedWithCard", () => {
  it("lists members, badges the lead, marks 'you', and counts them", async () => {
    renderCard();
    expect(await screen.findByText(/shared with 2 members of blue/i)).toBeInTheDocument();
    expect(screen.getByText("neo")).toBeInTheDocument();
    expect(screen.getByText("trinity")).toBeInTheDocument();
    expect(screen.getByText("lead")).toBeInTheDocument(); // neo is the lead
    expect(screen.getByText("you")).toBeInTheDocument(); // current user is trinity
  });

  it("shows the read-only note for non-admins (no manage link)", async () => {
    renderCard();
    expect(await screen.findByText(/team leads and admins manage/i)).toBeInTheDocument();
    expect(screen.queryByRole("link", { name: /manage members/i })).not.toBeInTheDocument();
  });
});
