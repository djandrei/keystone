import { describe, expect, it, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { AppShell } from "./AppShell";
import { visibleNav } from "./nav";

function renderShell(role: "admin" | "analyst") {
  return render(
    <MemoryRouter>
      <AppShell user={{ username: "neo", role }} onLogout={vi.fn()}>
        <p>page body</p>
      </AppShell>
    </MemoryRouter>,
  );
}

describe("AppShell", () => {
  it("renders the wordmark, nav and children", () => {
    renderShell("analyst");
    expect(screen.getAllByLabelText("Keystone").length).toBeGreaterThan(0);
    expect(screen.getByRole("link", { name: /Dashboard/ })).toBeInTheDocument();
    expect(screen.getByText("page body")).toBeInTheDocument();
  });

  it("hides admin-only nav for non-admins", () => {
    renderShell("analyst");
    expect(screen.queryByRole("link", { name: /Settings/ })).not.toBeInTheDocument();
  });

  it("shows admin nav for admins", () => {
    renderShell("admin");
    expect(screen.getByRole("link", { name: /Settings/ })).toBeInTheDocument();
  });
});

describe("visibleNav", () => {
  it("filters by role", () => {
    expect(visibleNav("viewer").some((i) => i.roles?.includes("admin"))).toBe(false);
    expect(visibleNav("admin").some((i) => i.label === "Settings")).toBe(true);
  });
});
