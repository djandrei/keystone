import { Loader2 } from "lucide-react";
import { Badge } from "@/components/ui/badge";

/** "running now" pill in the top bar; hidden when nothing is active. */
export function RunningIndicator({ running }: { running: number }) {
  if (running <= 0) return null;
  return (
    <Badge variant="info" aria-label={`${running} running`}>
      <Loader2 className="h-3 w-3 animate-spin" />
      {running} running
    </Badge>
  );
}
