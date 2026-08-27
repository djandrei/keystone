import { Link } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { useCurrentUser } from "@/auth/AuthContext";
import { useTeam } from "@/team/TeamContext";
import { analysesApi } from "@/lib/analysisApi";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Table, TBody, TD, TH, THead, TR } from "@/components/ui/table";
import { Skeleton } from "@/components/ui/skeleton";
import { StatusPill } from "@/components/analysis/StatusPill";

export function DashboardPage() {
  const user = useCurrentUser();
  const { activeTeamId, teams } = useTeam();
  const { data: analyses, isLoading } = useQuery({
    queryKey: ["analyses", activeTeamId],
    queryFn: () => analysesApi.list(activeTeamId ? { team_id: activeTeamId } : undefined),
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

      {isLoading ? (
        <Skeleton className="h-40 w-full" />
      ) : analyses && analyses.length > 0 ? (
        <Table>
          <THead>
            <TR>
              <TH>ID</TH>
              <TH>Mode</TH>
              <TH>Analyst</TH>
              <TH>Status</TH>
              <TH>Created</TH>
              <TH className="text-right">Open</TH>
            </TR>
          </THead>
          <TBody>
            {analyses.map((a) => (
              <TR key={a.id}>
                <TD className="font-medium">#{a.id}</TD>
                <TD className="uppercase text-fg-muted">{a.mode}</TD>
                <TD className="text-fg-muted">{a.created_by_username ?? "—"}</TD>
                <TD>
                  <StatusPill status={a.status} />
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
            ))}
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
