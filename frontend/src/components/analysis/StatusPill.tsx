import { Badge } from "@/components/ui/badge";
import type { AnalysisStatus } from "@/lib/analysisApi";

const MAP: Record<AnalysisStatus, { variant: "default" | "info" | "good" | "critical" | "warn"; label: string }> = {
  queued: { variant: "default", label: "queued" },
  running: { variant: "info", label: "running" },
  succeeded: { variant: "good", label: "succeeded" },
  failed: { variant: "critical", label: "failed" },
  canceled: { variant: "warn", label: "canceled" },
};

export function StatusPill({ status }: { status: AnalysisStatus }) {
  const { variant, label } = MAP[status];
  return <Badge variant={variant}>{label}</Badge>;
}
