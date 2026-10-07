import { describe, expect, it } from "vitest";
import { render, screen } from "@testing-library/react";
import { foldSteps, StepsPanel } from "./StepsPanel";
import { ReportView } from "./ReportView";
import { StatusPill } from "./StatusPill";
import type { StreamEvent } from "@/lib/analysisApi";

const events: StreamEvent[] = [
  { type: "step_start", step: "overview", seq: 1 },
  { type: "step_finish", step: "overview", seq: 2, data: { imports: 3 } },
  { type: "step_start", step: "analyze", seq: 3 },
];

describe("foldSteps", () => {
  it("folds the stream into ordered steps with state", () => {
    const steps = foldSteps(events);
    expect(steps.map((s) => [s.name, s.state])).toEqual([
      ["overview", "done"],
      ["analyze", "running"],
    ]);
    expect(steps[0].detail).toContain("imports: 3");
  });

  it("marks the last step errored on an error event", () => {
    const steps = foldSteps([...events, { type: "error", message: "boom" }]);
    expect(steps[1].state).toBe("error");
    expect(steps[1].detail).toBe("boom");
  });
});

describe("StepsPanel / ReportView / StatusPill", () => {
  it("renders steps", () => {
    render(<StepsPanel events={events} />);
    expect(screen.getByText("overview")).toBeInTheDocument();
    expect(screen.getByText("analyze")).toBeInTheDocument();
  });

  it("renders RE report fields including language runtime", () => {
    render(
      <ReportView
        result={{
          binary_type: "cli_tool",
          purpose: "lists files",
          key_functions: "main",
          attack_surface: "argv",
          language_runtime: "C",
          tool_calls: 3,
        }}
      />,
    );
    expect(screen.getByText("lists files")).toBeInTheDocument();
    expect(screen.getAllByText("C").length).toBeGreaterThan(0);
  });

  it("maps status to a pill", () => {
    render(<StatusPill status="succeeded" />);
    expect(screen.getByText("succeeded")).toBeInTheDocument();
  });
});

describe("SecurityBanner", () => {
  it("warns when injection is suspected and stays hidden otherwise", async () => {
    const { SecurityBanner } = await import("./SecurityBanner");
    const { container, rerender } = render(<SecurityBanner security={{ suspected: false }} />);
    expect(container).toBeEmptyDOMElement();
    rerender(
      <SecurityBanner
        security={{ suspected: true, narrative_hits: ["do not flag"], evidence: ["REVIEWER NOTICE…"] }}
      />,
    );
    expect(screen.getByRole("alert")).toHaveTextContent(/possible prompt injection/i);
    expect(screen.getByText(/REVIEWER NOTICE/)).toBeInTheDocument();
  });
});
