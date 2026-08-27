import { CheckCircle2, Loader2, Circle, XCircle } from "lucide-react";
import { cn } from "@/lib/cn";
import type { StreamEvent } from "@/lib/analysisApi";

type StepState = "running" | "done" | "error";
interface Step {
  name: string;
  state: StepState;
  detail?: string;
}

/** Fold the event stream into ordered, collapsible steps (one per pipeline stage). */
export function foldSteps(events: StreamEvent[]): Step[] {
  const order: string[] = [];
  const byName = new Map<string, Step>();
  for (const e of events) {
    if (e.type === "step_start" && e.step) {
      if (!byName.has(e.step)) order.push(e.step);
      byName.set(e.step, { name: e.step, state: "running" });
    } else if (e.type === "step_finish" && e.step) {
      const detail = e.data ? Object.entries(e.data).map(([k, v]) => `${k}: ${v}`).join(", ") : undefined;
      byName.set(e.step, { name: e.step, state: "done", detail });
    } else if (e.type === "error") {
      const last = order[order.length - 1];
      if (last) byName.set(last, { name: last, state: "error", detail: e.message });
    }
  }
  return order.map((n) => byName.get(n)!);
}

const ICON: Record<StepState, typeof Circle> = {
  running: Loader2,
  done: CheckCircle2,
  error: XCircle,
};

export function StepsPanel({ events }: { events: StreamEvent[] }) {
  const steps = foldSteps(events);
  if (steps.length === 0) {
    return <p className="text-sm text-fg-muted">Waiting for the analysis to start…</p>;
  }
  return (
    <ol className="flex flex-col gap-2" aria-label="Analysis steps">
      {steps.map((step) => {
        const Icon = ICON[step.state];
        return (
          <li
            key={step.name}
            className="flex items-start gap-3 rounded-lg border border-border bg-panel-2 px-3 py-2"
          >
            <Icon
              className={cn(
                "mt-0.5 h-4 w-4 shrink-0",
                step.state === "running" && "animate-spin text-info",
                step.state === "done" && "text-good",
                step.state === "error" && "text-critical",
              )}
            />
            <div className="flex flex-col">
              <span className="text-sm font-medium capitalize text-fg">{step.name}</span>
              {step.detail && <span className="text-xs text-fg-muted">{step.detail}</span>}
            </div>
          </li>
        );
      })}
    </ol>
  );
}
