import { createContext, useContext, useEffect, useMemo, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { teamsApi, type Team } from "@/lib/adminApi";

interface TeamValue {
  teams: Team[];
  activeTeamId: number | null;
  setActiveTeamId: (id: number) => void;
}

const DEFAULT: TeamValue = { teams: [], activeTeamId: null, setActiveTeamId: () => {} };
const TeamContext = createContext<TeamValue>(DEFAULT);
const STORAGE_KEY = "kst_active_team";

/** Never throws — components outside the provider get the empty default. */
export function useTeam(): TeamValue {
  return useContext(TeamContext);
}

function readStored(): number | null {
  try {
    const v = localStorage.getItem(STORAGE_KEY);
    return v ? Number(v) : null;
  } catch {
    return null;
  }
}

export function TeamProvider({ children }: { children: React.ReactNode }) {
  const { data: teams } = useQuery({ queryKey: ["teams"], queryFn: teamsApi.list });
  const [activeTeamId, setActive] = useState<number | null>(readStored);

  // default to the first team once loaded, if nothing valid is selected
  useEffect(() => {
    if (!teams || teams.length === 0) return;
    const valid = activeTeamId != null && teams.some((t) => t.id === activeTeamId);
    if (!valid) setActive(teams[0].id);
  }, [teams, activeTeamId]);

  const setActiveTeamId = (id: number) => {
    setActive(id);
    try {
      localStorage.setItem(STORAGE_KEY, String(id));
    } catch {
      /* storage unavailable */
    }
  };

  const value = useMemo(
    () => ({ teams: teams ?? [], activeTeamId, setActiveTeamId }),
    [teams, activeTeamId],
  );
  return <TeamContext.Provider value={value}>{children}</TeamContext.Provider>;
}
