import { useParams } from "react-router-dom";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { analysesApi } from "@/lib/analysisApi";
import { useAnalysisStream } from "@/lib/useAnalysisStream";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { StepsPanel } from "@/components/analysis/StepsPanel";
import { StatusPill } from "@/components/analysis/StatusPill";
import { ReportView } from "@/components/analysis/ReportView";
import { RulePicker } from "@/components/analysis/RulePicker";
import { FindingsView } from "@/components/analysis/FindingsView";
import { ExportBar } from "@/components/analysis/ExportBar";
import { SecurityBanner } from "@/components/analysis/SecurityBanner";

const ACTIVE = new Set(["queued", "running"]);

export function AnalysisPage() {
  const { id } = useParams();
  const analysisId = Number(id);
  const qc = useQueryClient();

  const { data: analysis, isLoading } = useQuery({
    queryKey: ["analysis", analysisId],
    queryFn: () => analysesApi.get(analysisId),
    refetchInterval: (q) => (ACTIVE.has(q.state.data?.status ?? "") ? 2000 : false),
  });

  const active = analysis ? ACTIVE.has(analysis.status) : false;
  const isVr = analysis?.mode === "vr";
  const { events, status: streamStatus } = useAnalysisStream(
    analysisId,
    active,
    analysis?.progress?.events ?? [],
  );

  const { data: report } = useQuery({
    queryKey: ["report", analysisId],
    queryFn: () => analysesApi.report(analysisId),
    enabled: analysis?.status === "succeeded",
  });

  const { data: findings } = useQuery({
    queryKey: ["findings", analysisId],
    queryFn: () => analysesApi.findings(analysisId),
    enabled: isVr && analysis?.status === "succeeded",
  });

  const cancel = useMutation({
    mutationFn: () => analysesApi.cancel(analysisId),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["analysis", analysisId] }),
  });

  const selectRule = useMutation({
    mutationFn: (rule: string) => analysesApi.selectRule(analysisId, rule),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["analysis", analysisId] }),
  });

  if (isLoading || !analysis) return <Skeleton className="h-64 w-full" />;

  const shownEvents = active && events.length ? events : analysis.progress?.events ?? [];
  // a pending rule pick: a needs_input event whose choice hasn't been made yet
  const needsInput = active
    ? [...shownEvents].reverse().find((e) => e.type === "needs_input")
    : undefined;
  const rulePicked = Boolean(analysis.params?.rule);

  return (
    <div className="flex flex-col gap-6">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <h1 className="text-2xl font-bold text-fg">Analysis #{analysis.id}</h1>
          <StatusPill status={analysis.status} />
          <span className="text-sm uppercase text-fg-muted">{analysis.mode}</span>
        </div>
        <div className="flex items-center gap-2">
          {analysis.status === "succeeded" && <ExportBar analysisId={analysis.id} markdown={report} />}
          {active && (
            <Button variant="secondary" disabled={cancel.isPending} onClick={() => cancel.mutate()}>
              Cancel
            </Button>
          )}
        </div>
      </div>

      <SecurityBanner security={analysis.security} />

      {needsInput && !rulePicked && (
        <RulePicker
          classes={(needsInput.data?.classes as Record<string, number>) ?? {}}
          pending={selectRule.isPending}
          onPick={(rule) => selectRule.mutate(rule)}
        />
      )}

      <Card>
        <CardHeader>
          <CardTitle>Steps</CardTitle>
        </CardHeader>
        <CardContent>
          {active && streamStatus === "closed" && (
            <p role="status" className="mb-3 text-xs text-warn">
              Live updates disconnected — the view still refreshes every few seconds.
            </p>
          )}
          <StepsPanel events={shownEvents} />
        </CardContent>
      </Card>

      {analysis.status === "failed" && analysis.error && (
        <Card>
          <CardHeader>
            <CardTitle className="text-critical">Failed</CardTitle>
          </CardHeader>
          <CardContent>
            <pre className="overflow-x-auto whitespace-pre-wrap font-mono text-xs text-critical">{analysis.error}</pre>
          </CardContent>
        </Card>
      )}

      {analysis.status === "succeeded" && isVr && (
        <Card>
          <CardHeader>
            <CardTitle>Vulnerability findings</CardTitle>
          </CardHeader>
          <CardContent>
            <FindingsView findings={findings ?? []} />
          </CardContent>
        </Card>
      )}

      {analysis.status === "succeeded" && !isVr && <ReportView result={analysis.re_result} markdown={report} />}
    </div>
  );
}
