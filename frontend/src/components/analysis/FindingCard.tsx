import { Badge } from "@/components/ui/badge";
import { cn } from "@/lib/cn";
import type { VRFindingRow } from "@/lib/analysisApi";

const CLASS_VARIANT = {
  true_positive: "critical",
  needs_review: "warn",
  false_positive: "default",
} as const;

const RISK_VARIANT = {
  critical: "critical",
  high: "critical",
  medium: "warn",
  low: "info",
  informational: "default",
} as const;

export function FindingCard({ finding: f }: { finding: VRFindingRow }) {
  return (
    <div className="flex flex-col gap-2 rounded-xl border border-border bg-panel p-4">
      <div className="flex flex-wrap items-center gap-2">
        <span className="font-mono text-sm text-fg">{f.rule}</span>
        <span className="text-xs text-fg-muted">
          {f.file}
          {f.line ? `:${f.line}` : ""}
        </span>
        <div className="ml-auto flex gap-2">
          {f.classification && (
            <Badge variant={CLASS_VARIANT[f.classification]}>{f.classification.replace("_", " ")}</Badge>
          )}
          {f.risk_level && <Badge variant={RISK_VARIANT[f.risk_level]}>{f.risk_level}</Badge>}
          {f.cwe_id && <Badge variant="info">{f.cwe_id}</Badge>}
        </div>
      </div>
      {f.reasoning && <p className="text-sm text-fg-muted">{f.reasoning}</p>}
      {f.reachable && (
        <div className={cn("rounded-lg px-3 py-2 text-xs", f.reachable === "yes" ? "bg-critical/10 text-critical" : "bg-panel-2 text-fg-muted")}>
          <span className="font-medium">Reachable: {f.reachable}</span>
          {f.confidence ? ` · confidence ${f.confidence}` : ""}
          {f.entry_path ? ` · ${f.entry_path}` : ""}
        </div>
      )}
    </div>
  );
}
