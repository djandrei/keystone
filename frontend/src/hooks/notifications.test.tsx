import { describe, expect, it } from "vitest";
import { render, screen } from "@testing-library/react";
import { diffCompletions } from "./useAnalysisNotifications";
import { RunningIndicator } from "@/components/shell/RunningIndicator";
import type { AnalysisRow, AnalysisStatus } from "@/lib/analysisApi";

function row(id: number, status: AnalysisStatus): AnalysisRow {
  return {
    id, team_id: 1, binary_id: 1, mode: "re", status, model: null, params: null,
    created_by: 1, created_at: null, started_at: null, finished_at: null, error: null, progress: null,
  };
}

describe("diffCompletions", () => {
  it("detects active -> terminal transitions and counts running", () => {
    const prev = new Map<number, AnalysisStatus>([
      [1, "running"],
      [2, "queued"],
      [3, "succeeded"],
    ]);
    const list = [row(1, "succeeded"), row(2, "queued"), row(3, "succeeded"), row(4, "running")];
    const { completions, running } = diffCompletions(prev, list);
    expect(completions).toEqual([{ id: 1, status: "succeeded" }]); // 2 still queued, 3 unchanged
    expect(running).toBe(2); // #2 queued + #4 running
  });

  it("fires nothing on first sight (no prior state)", () => {
    const { completions } = diffCompletions(new Map(), [row(1, "succeeded")]);
    expect(completions).toEqual([]);
  });

  it("reports failure transitions too", () => {
    const prev = new Map<number, AnalysisStatus>([[9, "running"]]);
    const { completions } = diffCompletions(prev, [row(9, "failed")]);
    expect(completions).toEqual([{ id: 9, status: "failed" }]);
  });
});

describe("RunningIndicator", () => {
  it("shows the count when analyses are running", () => {
    render(<RunningIndicator running={3} />);
    expect(screen.getByText(/3 running/)).toBeInTheDocument();
  });

  it("renders nothing when idle", () => {
    const { container } = render(<RunningIndicator running={0} />);
    expect(container).toBeEmptyDOMElement();
  });
});
