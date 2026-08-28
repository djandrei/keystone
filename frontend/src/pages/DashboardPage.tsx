import { useState } from "react";
import { Link } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { useCurrentUser } from "@/auth/AuthContext";
import { useTeam } from "@/team/TeamContext";
import { analysesApi, type AnalysisStatus } from "@/lib/analysisApi";
import { describeTask } from "@/lib/describeTask";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Table, TBody, TD, TH, THead, TR } from "@/components/ui/table";
import { Skeleton } from "@/components/ui/skeleton";
import { StatusPill } from "@/components/analysis/StatusPill";
import { ShieldAlert } from "lucide-react";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";

const STATUSES: (AnalysisStatus | "all")[] = ["all", "queued", "running", "succeeded", "failed", "canceled"];

export function DashboardPage() {
  const user = useCurrentUser();
  const { activeTeamId, teams } = useTeam();
  const [q, setQ] = useState("");
  const [status, setStatus] = useState<AnalysisStatus | "all">("all");

  const { data: analyses, isLoading } = useQuery({
    queryKey: ["analyses", activeTeamId, q, status],
    queryFn: () =>
      analysesApi.list({
        ...(activeTeamId ? { team_id: activeTeamId } : {}),
        ...(q ? { q } : {}),
        ...(status !== "all" ? { status } : {}),
      }),
  });
  const activeTeam = teams.find((t) => t.id === activeTeamId);

  return (
    <div className="flex flex-col gap-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-fg">Welcome back, {user.username}</h1>
          <p className="mt-1 text-fg-muted">Recent analyses{activeTeam ? ` in ${activeTeam.name}` : ""}.</p>
        </div>
        <Button asChild>
          <Link to="/binaries">Upload &amp; analyze</Link>
        </Button>
      </div>

      <div className="flex flex-wrap items-end gap-3">
        <div className="flex-1 min-w-48">
          <Input
            aria-label="Search analyses"
            placeholder="Search by binary filename…"
            value={q}
            onChange={(e) => setQ(e.target.value)}
          />
        </div>
        <Select value={status} onValueChange={(v) => setStatus(v as AnalysisStatus | "all")}>
          <SelectTrigger aria-label="Status filter" className="w-40">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            {STATUSES.map((s) => (
              <SelectItem key={s} value={s}>
                {s}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
      </div>

      {isLoading ? (
        <Skeleton className="h-40 w-full" />
      ) : analyses && analyses.length > 0 ? (
        <Table>
          <THead>
            <TR>
              <TH>ID</TH>
              <TH>Mode</TH>
              <TH>Task</TH>
              <TH>Analyst</TH>
              <TH>Status</TH>
              <TH>Created</TH>
              <TH className="text-right">Open</TH>
            </TR>
          </THead>
          <TBody>
            {analyses.map((a) => {
              const task = describeTask(a);
              return (
              <TR key={a.id}>
                <TD className="font-medium">#{a.id}</TD>
                <TD className="uppercase text-fg-muted">{a.mode}</TD>
                <TD>
                  <div className="max-w-[16rem]">
                    <div className="truncate font-medium text-fg" title={task.target}>{task.target}</div>
                    <div className="truncate text-xs text-fg-muted" title={task.detail}>{task.detail}</div>
                  </div>
                </TD>
                <TD className="text-fg-muted">{a.created_by_username ?? "—"}</TD>
                <TD>
                  <span className="flex items-center gap-1.5">
                    <StatusPill status={a.status} />
                    {a.security?.suspected && (
                      <ShieldAlert className="h-4 w-4 text-critical" aria-label="injection flagged" />
                    )}
                  </span>
                </TD>
                <TD className="text-fg-muted">{a.created_at?.slice(0, 16).replace("T", " ")}</TD>
                <TD>
                  <div className="flex justify-end">
                    <Button asChild size="sm" variant="secondary">
                      <Link to={`/analyses/${a.id}`}>View</Link>
                    </Button>
                  </div>
                </TD>
              </TR>
              );
            })}
          </TBody>
        </Table>
      ) : (
        <Card>
          <CardHeader>
            <CardTitle>No analyses yet</CardTitle>
            <CardDescription>Upload a binary and run an RE analysis to get started.</CardDescription>
          </CardHeader>
          <CardContent>
            <Button asChild>
              <Link to="/binaries">Go to Binaries</Link>
            </Button>
          </CardContent>
        </Card>
      )}
    </div>
  );
}
