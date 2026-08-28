import { useQuery } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import { Users } from "lucide-react";
import { teamsApi } from "@/lib/adminApi";
import { useCurrentUser } from "@/auth/AuthContext";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";

/** Surfaces the sharing that already exists: every project and binary in a team is
 *  shared with all of that team's members. Read-only for non-admins. */
export function SharedWithCard({ teamId }: { teamId: number | null }) {
  const user = useCurrentUser();
  const { data: team } = useQuery({
    queryKey: ["team", teamId],
    queryFn: () => teamsApi.get(teamId!),
    enabled: teamId != null,
  });
  if (!team) return null;
  const members = team.members ?? [];
  const label = `${members.length} ${members.length === 1 ? "member" : "members"}`;

  return (
    <Card>
      <CardHeader className="flex-row items-center gap-2 space-y-0">
        <Users className="h-4 w-4 text-fg-muted" />
        <CardTitle className="text-base">
          Shared with {label} of {team.name}
        </CardTitle>
      </CardHeader>
      <CardContent className="flex flex-col gap-3">
        <div className="flex flex-wrap gap-2">
          {members.map((m) => (
            <span
              key={m.user_id}
              className="flex items-center gap-1.5 rounded-full border border-border bg-panel-2 px-3 py-1 text-sm text-fg"
            >
              {m.username}
              {m.user_id === user.id && <Badge variant="info">you</Badge>}
              {m.team_role === "lead" && <Badge variant="amber">lead</Badge>}
            </span>
          ))}
        </div>
        <p className="text-sm text-fg-muted">
          Everyone on the team can browse these projects and run analyses.{" "}
          {user.role === "admin" ? (
            <Link to="/admin/teams" className="text-amber underline">
              Manage members
            </Link>
          ) : (
            "Team leads and admins manage who's on the team."
          )}
        </p>
      </CardContent>
    </Card>
  );
}
