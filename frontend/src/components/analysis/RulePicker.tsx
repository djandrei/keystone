import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";

/** One rule class the scan found, as ranked by the engine. */
export interface RuleClassSummary {
  rule: string;
  count: number;
  severity: string | null;
}

const SEVERITY_VARIANT: Record<string, "critical" | "warn" | "info"> = {
  ERROR: "critical",
  WARNING: "warn",
  INFO: "info",
};

/**
 * Shown when the VR pipeline pauses on a needs_input event: pick a rule class.
 *
 * The list arrives already ranked by the engine (highest declared severity first,
 * then volume) and is rendered in that order — the human sees the same ordering
 * the automatic pick uses, so the two cannot silently disagree. `classes` is the
 * pre-severity fallback for analyses whose events predate `class_summary`.
 */
export function RulePicker({
  classes,
  summary,
  auto,
  onPick,
  pending,
}: {
  classes: Record<string, number>;
  summary?: RuleClassSummary[];
  auto?: string | null;
  onPick: (rule: string) => void;
  pending?: boolean;
}) {
  const entries: RuleClassSummary[] =
    summary && summary.length
      ? summary
      : Object.entries(classes)
          .sort((a, b) => b[1] - a[1])
          .map(([rule, count]) => ({ rule, count, severity: null }));

  return (
    <Card>
      <CardHeader>
        <CardTitle>Choose a rule class to investigate</CardTitle>
        <CardDescription>
          Ranked by severity, then volume. Only the class you pick is triaged — the rest are
          counted but not sent to the model.
        </CardDescription>
      </CardHeader>
      <CardContent className="flex flex-wrap gap-2">
        {entries.map(({ rule, count, severity }) => (
          <Button
            key={rule}
            variant="secondary"
            disabled={pending}
            onClick={() => onPick(rule)}
            title={severity ? `${severity} · ${count} findings` : `${count} findings`}
          >
            {severity && (
              <Badge variant={SEVERITY_VARIANT[severity] ?? "default"}>{severity}</Badge>
            )}
            {rule} <span className="ml-1 text-fg-muted">({count})</span>
            {auto === rule && <span className="ml-1 text-xs text-fg-muted">· default</span>}
          </Button>
        ))}
      </CardContent>
    </Card>
  );
}
