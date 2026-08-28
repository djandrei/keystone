import type { AnalysisRow } from "./analysisApi";

/** A brief two-line description of an analysis "task" for the Dashboard: the
 *  binary it targets, and an outcome line that adapts to status — the RE purpose
 *  or VR findings summary once finished, else a plain state word. */
export function describeTask(a: AnalysisRow): { target: string; detail: string } {
  return { target: a.binary_filename ?? `binary #${a.binary_id}`, detail: taskDetail(a) };
}

function taskDetail(a: AnalysisRow): string {
  switch (a.status) {
    case "queued":
      return "queued";
    case "running":
      return "analyzing…";
    case "canceled":
      return "canceled";
    case "failed":
      return "failed";
  }
  // succeeded — describe the result
  const s = a.summary;
  if (s?.kind === "re") return s.purpose ?? "analysis complete";
  if (s?.kind === "vr") {
    if (s.count === 0) return "no findings";
    const bits = [`${s.count} finding${s.count === 1 ? "" : "s"}`];
    if (s.top_risk) bits.push(s.top_risk);
    if (s.top_cwe) bits.push(s.top_cwe);
    return bits.join(" · ");
  }
  return a.mode === "vr" ? "scan complete" : "analysis complete";
}
