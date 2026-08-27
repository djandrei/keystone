import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import type { REResultView } from "@/lib/analysisApi";

function Field({ label, value }: { label: string; value: string | null }) {
  return (
    <div className="flex flex-col gap-1">
      <span className="text-xs font-medium uppercase tracking-wide text-fg-muted">{label}</span>
      <p className="text-sm text-fg">{value || "—"}</p>
    </div>
  );
}

export function ReportView({ result, markdown }: { result?: REResultView; markdown?: string }) {
  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-3">
          RE Report
          {result?.language_runtime && <Badge variant="amber">{result.language_runtime}</Badge>}
        </CardTitle>
      </CardHeader>
      <CardContent className="flex flex-col gap-4">
        {result ? (
          <div className="grid gap-4 sm:grid-cols-2">
            <Field label="Binary type" value={result.binary_type} />
            <Field label="Language / runtime" value={result.language_runtime} />
            <div className="sm:col-span-2">
              <Field label="Purpose" value={result.purpose} />
            </div>
            <div className="sm:col-span-2">
              <Field label="Key functions" value={result.key_functions} />
            </div>
            <div className="sm:col-span-2">
              <Field label="Attack surface" value={result.attack_surface} />
            </div>
          </div>
        ) : (
          <p className="text-sm text-fg-muted">No structured result.</p>
        )}
        {markdown && (
          <details className="rounded-lg border border-border bg-panel-2 p-3">
            <summary className="cursor-pointer text-sm text-fg-muted">Full markdown report</summary>
            <pre className="mt-2 overflow-x-auto whitespace-pre-wrap font-mono text-xs text-fg">{markdown}</pre>
          </details>
        )}
      </CardContent>
    </Card>
  );
}
