import { describe, expect, it } from "vitest";
import { describeTask } from "./describeTask";
import type { AnalysisRow } from "./analysisApi";

function row(over: Partial<AnalysisRow>): AnalysisRow {
  return {
    id: 1, team_id: 1, binary_id: 7, mode: "re", status: "succeeded", model: null,
    params: null, created_by: 1, created_at: null, started_at: null, finished_at: null,
    error: null, progress: null, binary_filename: "crackme2.x86_64", summary: null,
    ...over,
  };
}

describe("describeTask", () => {
  it("RE succeeded shows the purpose", () => {
    const d = describeTask(row({ summary: { kind: "re", purpose: "A CLI string tool" } }));
    expect(d).toEqual({ target: "crackme2.x86_64", detail: "A CLI string tool" });
  });

  it("VR succeeded summarizes the findings", () => {
    const d = describeTask(
      row({ mode: "vr", summary: { kind: "vr", count: 1, top_risk: "high", top_cwe: "CWE-798" } }),
    );
    expect(d.detail).toBe("1 finding · high · CWE-798");
  });

  it("VR with multiple findings pluralizes", () => {
    const d = describeTask(
      row({ mode: "vr", summary: { kind: "vr", count: 3, top_risk: "medium", top_cwe: null } }),
    );
    expect(d.detail).toBe("3 findings · medium");
  });

  it("VR with no findings says so", () => {
    const d = describeTask(
      row({ mode: "vr", summary: { kind: "vr", count: 0, top_risk: null, top_cwe: null } }),
    );
    expect(d.detail).toBe("no findings");
  });

  it("unfinished states use a plain word", () => {
    expect(describeTask(row({ status: "running", summary: null })).detail).toBe("analyzing…");
    expect(describeTask(row({ status: "queued", summary: null })).detail).toBe("queued");
    expect(describeTask(row({ status: "failed", summary: null })).detail).toBe("failed");
  });

  it("falls back to a binary-id target when the filename is missing", () => {
    const d = describeTask(row({ binary_filename: null, status: "running" }));
    expect(d.target).toBe("binary #7");
  });
});
