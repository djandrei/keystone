import { Users } from "lucide-react";
import { useTeam } from "@/team/TeamContext";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";

/** Active-team selector for multi-team users; hidden when there's 0–1 team. */
export function TeamSwitcher() {
  const { teams, activeTeamId, setActiveTeamId } = useTeam();
  if (teams.length < 2) return null;
  return (
    <div className="flex items-center gap-2">
      <Users className="h-4 w-4 text-fg-muted" />
      <Select value={activeTeamId ? String(activeTeamId) : ""} onValueChange={(v) => setActiveTeamId(Number(v))}>
        <SelectTrigger aria-label="Active team" className="h-8 w-40">
          <SelectValue placeholder="Team" />
        </SelectTrigger>
        <SelectContent>
          {teams.map((t) => (
            <SelectItem key={t.id} value={String(t.id)}>
              {t.name}
            </SelectItem>
          ))}
        </SelectContent>
      </Select>
    </div>
  );
}
