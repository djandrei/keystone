import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";

/** Shown when the VR pipeline pauses on a needs_input event: pick a rule class. */
export function RulePicker({
  classes,
  onPick,
  pending,
}: {
  classes: Record<string, number>;
  onPick: (rule: string) => void;
  pending?: boolean;
}) {
  const entries = Object.entries(classes).sort((a, b) => b[1] - a[1]);
  return (
    <Card>
      <CardHeader>
        <CardTitle>Choose a rule class to investigate</CardTitle>
        <CardDescription>Semgrep grouped its hits — pick which class to triage.</CardDescription>
      </CardHeader>
      <CardContent className="flex flex-wrap gap-2">
        {entries.map(([rule, count]) => (
          <Button key={rule} variant="secondary" disabled={pending} onClick={() => onPick(rule)}>
            {rule} <span className="ml-1 text-fg-muted">({count})</span>
          </Button>
        ))}
      </CardContent>
    </Card>
  );
}
