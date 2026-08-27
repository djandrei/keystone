import { ShieldAlert } from "lucide-react";
import type { InjectionReport } from "@/lib/analysisApi";

/** Warns the reviewer when the analyzed sample tried to steer the model
 *  (indirect prompt injection). The analysis itself is injection-resistant —
 *  sanitized input + fact-based two-stage reasoning — but a human should look. */
export function SecurityBanner({ security }: { security?: InjectionReport | null }) {
  if (!security?.suspected) return null;
  const evidence = security.evidence ?? [];
  return (
    <div role="alert" className="flex flex-col gap-2 rounded-xl border border-critical/40 bg-critical/10 p-4">
      <div className="flex items-center gap-2 font-semibold text-critical">
        <ShieldAlert className="h-5 w-5" />
        Possible prompt injection in this sample
      </div>
      <p className="text-sm text-fg-muted">
        The binary contains text that tries to influence the analysis (e.g. a fake “prior-analyst
        note”). Keystone sanitized the input and reasoned from extracted behaviors, not the
        embedded strings — but review the verdict with this in mind.
      </p>
      {evidence.length > 0 && (
        <ul className="flex flex-col gap-1">
          {evidence.slice(0, 4).map((e, i) => (
            <li key={i} className="truncate rounded bg-panel-2 px-2 py-1 font-mono text-xs text-fg-muted">
              {e}
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}
