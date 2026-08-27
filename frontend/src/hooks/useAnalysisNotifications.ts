import { useEffect, useRef } from "react";
import { useQuery } from "@tanstack/react-query";
import { analysesApi, type AnalysisRow, type AnalysisStatus } from "@/lib/analysisApi";
import { useTeam } from "@/team/TeamContext";
import { useToast } from "@/components/ui/toast";

const ACTIVE: ReadonlySet<AnalysisStatus> = new Set(["queued", "running"]);
const TERMINAL: ReadonlySet<AnalysisStatus> = new Set(["succeeded", "failed", "canceled"]);

export interface Completion {
  id: number;
  status: AnalysisStatus;
}

/** Pure: which analyses just transitioned active -> terminal, and how many are
 *  still active. */
export function diffCompletions(
  prev: Map<number, AnalysisStatus>,
  list: AnalysisRow[],
): { completions: Completion[]; running: number } {
  const completions: Completion[] = [];
  for (const a of list) {
    const before = prev.get(a.id);
    if (before && ACTIVE.has(before) && TERMINAL.has(a.status)) {
      completions.push({ id: a.id, status: a.status });
    }
  }
  return { completions, running: list.filter((a) => ACTIVE.has(a.status)).length };
}

const TOAST_VARIANT: Record<string, "success" | "error" | "default"> = {
  succeeded: "success",
  failed: "error",
  canceled: "default",
};

/** Polls recent analyses; toasts on completion/failure and reports how many run. */
export function useAnalysisNotifications(): { running: number } {
  const toast = useToast();
  const { activeTeamId } = useTeam();
  const prev = useRef<Map<number, AnalysisStatus>>(new Map());

  const { data } = useQuery({
    queryKey: ["analyses", "notify", activeTeamId],
    queryFn: () => analysesApi.list(activeTeamId ? { team_id: activeTeamId, limit: 50 } : { limit: 50 }),
    refetchInterval: 5000,
  });

  useEffect(() => {
    if (!data) return;
    const { completions } = diffCompletions(prev.current, data);
    for (const c of completions) {
      toast({ title: `Analysis #${c.id} ${c.status}`, variant: TOAST_VARIANT[c.status] ?? "default" });
    }
    prev.current = new Map(data.map((a) => [a.id, a.status]));
  }, [data, toast]);

  return { running: data ? diffCompletions(prev.current, data).running : 0 };
}
