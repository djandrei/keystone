import { Table, TBody, TD, TH, THead, TR } from "@/components/ui/table";
import { Badge } from "@/components/ui/badge";
import type { VRFindingRow } from "@/lib/analysisApi";
import { FindingCard } from "./FindingCard";

/** Rule x count summary + triage cards for the suspicious findings. */
export function FindingsView({ findings }: { findings: VRFindingRow[] }) {
  const byRule = new Map<string, number>();
  for (const f of findings) byRule.set(f.rule ?? "unknown", (byRule.get(f.rule ?? "unknown") ?? 0) + 1);
  const suspicious = findings.filter((f) => f.classification === "true_positive" || f.classification === "needs_review");

  return (
    <div className="flex flex-col gap-4">
      <Table>
        <THead>
          <TR>
            <TH>Rule</TH>
            <TH className="text-right">Findings</TH>
          </TR>
        </THead>
        <TBody>
          {[...byRule.entries()].map(([rule, count]) => (
            <TR key={rule}>
              <TD className="font-mono">{rule}</TD>
              <TD className="text-right">
                <Badge>{count}</Badge>
              </TD>
            </TR>
          ))}
        </TBody>
      </Table>

      <h3 className="text-sm font-semibold uppercase tracking-wide text-fg-muted">
        Suspicious findings ({suspicious.length})
      </h3>
      <div className="flex flex-col gap-3">
        {suspicious.map((f) => (
          <FindingCard key={f.id} finding={f} />
        ))}
        {suspicious.length === 0 && <p className="text-sm text-fg-muted">None survived triage.</p>}
      </div>
    </div>
  );
}
