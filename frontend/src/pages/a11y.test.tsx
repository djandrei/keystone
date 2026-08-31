import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";
import { render } from "@testing-library/react";
import { axe } from "jest-axe";
import { MemoryRouter } from "react-router-dom";
import { AuthProvider } from "@/auth/AuthContext";
import { ToastProvider } from "@/components/ui/toast";
import { server } from "@/tests/msw/server";
import { LoginPage } from "./LoginPage";
import { FindingCard } from "@/components/analysis/FindingCard";
import { RuleSetPicker } from "@/components/analysis/RuleSetPicker";
import { FunctionsPanel } from "@/components/analysis/FunctionsPanel";
import { vi } from "vitest";

vi.mock("@/auth/AuthContext", async (orig) => ({
  ...(await orig<Record<string, unknown>>()),
  useAuth: () => ({ user: { id: 1, username: "neo", email: "n@x", role: "analyst" } }),
}));
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { http, HttpResponse } from "msw";

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

  it("the rule-set picker has no violations", async () => {
    server.use(
      http.get("/api/rule-sets", () =>
        HttpResponse.json([
          {
            id: 3, team_id: null, name: "Decompiled C", description: null, languages: ["c"],
            is_builtin: true,
    attribution: { author: "Marco Ivaldi (raptor)", license: "MIT", url: "https://github.com/0xdea/semgrep-rules", commit: "33155497b25b4639193db016962af2df46290b10" }, archived: false, created_by: null, created_at: null,
            latest_version: {
              id: 30, version_no: 1, content_sha256: "x", rule_ids: ["a"], rule_count: 1,
              notes: null, security: null, created_by: null, created_at: null,
            },
          },
        ]),
      ),
    );
    const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    const { baseElement } = render(
      <ToastProvider>
        <QueryClientProvider client={qc}>
          <RuleSetPicker open onCancel={() => {}} onStart={() => {}} />
        </QueryClientProvider>
      </ToastProvider>,
    );
    // the picker renders into a portal, so axe the whole document body
    expect(await axe(baseElement)).toHaveNoViolations();
  });

  it("the functions panel has no violations", async () => {
    server.use(
      http.get("/api/analyses/77/functions", () =>
        HttpResponse.json([
          {
            id: 1, address: "401146", original_name: "FUN_401146",
            suggested_name: "parse_ioctl_header", display_name: "parse_ioctl_header",
            purpose: "Reads the IOCTL code.", source: "llm", included: true,
          },
        ]),
      ),
    );
    const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    const { container, findByText } = render(
      <ToastProvider>
        <QueryClientProvider client={qc}>
          <FunctionsPanel analysisId={77} />
        </QueryClientProvider>
      </ToastProvider>,
    );
    await findByText("parse_ioctl_header");
    expect(await axe(container)).toHaveNoViolations();
  });
});
