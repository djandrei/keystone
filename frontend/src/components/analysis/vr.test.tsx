import { describe, expect, it, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { RulePicker } from "./RulePicker";
import { FindingCard } from "./FindingCard";
import { FindingsView } from "./FindingsView";
import type { VRFindingRow } from "@/lib/analysisApi";

const FINDING: VRFindingRow = {
  id: 1, rule: "integer-overflow", file: "parse.c", line: 3, semgrep_message: "overflow",
  classification: "true_positive", risk_level: "high", cwe_id: "CWE-190",
  reasoning: "unchecked length", reachable: "yes", entry_path: "ioctl -> parse", confidence: "high",
};

describe("RulePicker", () => {
  it("renders classes sorted by count and fires onPick", async () => {
    const onPick = vi.fn();
    render(<RulePicker classes={{ "format-string": 1, "integer-overflow": 4 }} onPick={onPick} />);
    const buttons = screen.getAllByRole("button");
    expect(buttons[0]).toHaveTextContent("integer-overflow"); // higher count first
    await userEvent.click(screen.getByRole("button", { name: /format-string/ }));
    expect(onPick).toHaveBeenCalledWith("format-string");
  });
});

describe("FindingCard", () => {
  it("shows classification, risk, cwe and reachability", () => {
    render(<FindingCard finding={FINDING} />);
    expect(screen.getByText("true positive")).toBeInTheDocument();
    expect(screen.getByText("CWE-190")).toBeInTheDocument();
    expect(screen.getByText(/reachable: yes/i)).toBeInTheDocument();
  });
});

describe("FindingsView", () => {
  it("summarizes rule counts and lists suspicious findings", () => {
    const fp: VRFindingRow = { ...FINDING, id: 2, classification: "false_positive", reachable: null };
    render(<FindingsView findings={[FINDING, fp]} />);
    expect(screen.getByText("Suspicious findings (1)")).toBeInTheDocument();
    expect(screen.getByRole("cell", { name: "integer-overflow" })).toBeInTheDocument();
  });
});
