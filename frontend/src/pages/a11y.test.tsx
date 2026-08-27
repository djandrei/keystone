import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";
import { render } from "@testing-library/react";
import { axe } from "jest-axe";
import { MemoryRouter } from "react-router-dom";
import { AuthProvider } from "@/auth/AuthContext";
import { ToastProvider } from "@/components/ui/toast";
import { server } from "@/tests/msw/server";
import { LoginPage } from "./LoginPage";
import { FindingCard } from "@/components/analysis/FindingCard";

beforeAll(() => server.listen({ onUnhandledRequest: "error" }));
afterEach(() => server.resetHandlers());
afterAll(() => server.close());

describe("accessibility (axe)", () => {
  it("the login page has no violations", async () => {
    const { container } = render(
      <ToastProvider>
        <AuthProvider>
          <MemoryRouter>
            <LoginPage />
          </MemoryRouter>
        </AuthProvider>
      </ToastProvider>,
    );
    expect(await axe(container)).toHaveNoViolations();
  });

  it("a finding card has no violations", async () => {
    const { container } = render(
      <FindingCard
        finding={{
          id: 1, rule: "integer-overflow", file: "parse.c", line: 3, semgrep_message: "overflow",
          classification: "true_positive", risk_level: "high", cwe_id: "CWE-190",
          reasoning: "unchecked length", reachable: "yes", entry_path: "ioctl", confidence: "high",
        }}
      />,
    );
    expect(await axe(container)).toHaveNoViolations();
  });
});
