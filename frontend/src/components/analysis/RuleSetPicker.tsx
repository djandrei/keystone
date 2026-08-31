import { useEffect, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { ruleSetsApi } from "@/lib/ruleSetsApi";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Skeleton } from "@/components/ui/skeleton";
import {
  Modal,
  ModalContent,
  ModalHeader,
  ModalTitle,
  ModalDescription,
} from "@/components/ui/modal";

export interface VrStartOptions {
  rule_set_ids: number[];
  interactive: boolean;
}

/**
 * Shown when Run VR is clicked: choose which rule sets this scan uses.
 *
 * This is the *pre-scan* question ("what do we look for?"). The rule-class
 * picker that appears mid-run is the *post-scan* one ("of what we found, what
 * gets triaged?") — both exist and neither replaces the other.
 */
export function RuleSetPicker({
  open,
  defaultRuleSetId,
  pending,
  onCancel,
  onStart,
}: {
  open: boolean;
  /** Preselected on mount so the common case is one click. */
  defaultRuleSetId?: number | null;
  pending?: boolean;
  onCancel: () => void;
  onStart: (opts: VrStartOptions) => void;
}) {
  const { data: rows, isLoading } = useQuery({
    queryKey: ["rule-sets", "picker"],
    queryFn: () => ruleSetsApi.list({ include_builtin: 1 }),
    enabled: open,
  });

  const [selected, setSelected] = useState<number[]>([]);
  const [interactive, setInteractive] = useState(true);

  useEffect(() => {
    if (!rows || selected.length) return;
    const preselect =
      rows.find((r) => r.id === defaultRuleSetId) ?? rows.find((r) => r.is_builtin) ?? rows[0];
    if (preselect) setSelected([preselect.id]);
  }, [rows, defaultRuleSetId, selected.length]);

  const toggle = (id: number) =>
    setSelected((s) => (s.includes(id) ? s.filter((x) => x !== id) : [...s, id]));

  return (
    <Modal open={open} onOpenChange={(o) => !o && onCancel()}>
      <ModalContent>
        <ModalHeader>
          <ModalTitle>Run VR analysis</ModalTitle>
          <ModalDescription>
            Choose the Semgrep rule sets to scan the decompiled code with. The exact versions
            are recorded on the analysis.
          </ModalDescription>
        </ModalHeader>

        {isLoading ? (
          <Skeleton className="h-32 w-full" />
        ) : !rows?.length ? (
          <p className="text-sm text-fg-muted">
            No rule sets available. Create one under Rule sets first.
          </p>
        ) : (
          <ul className="flex max-h-64 flex-col gap-1 overflow-y-auto">
            {rows.map((r) => (
              <li key={r.id}>
                <label className="flex cursor-pointer items-center gap-2 rounded-lg p-2 hover:bg-panel-2">
                  <input
                    type="checkbox"
                    checked={selected.includes(r.id)}
                    onChange={() => toggle(r.id)}
                    aria-label={r.name}
                  />
                  <span className="text-sm text-fg">{r.name}</span>
                  {r.is_builtin && <Badge variant="default">Built-in</Badge>}
                  <span className="ml-auto text-xs text-fg-muted">
                    {r.latest_version ? `v${r.latest_version.version_no}` : "no versions"} ·{" "}
                    {r.latest_version?.rule_count ?? 0} rules
                  </span>
                </label>
              </li>
            ))}
          </ul>
        )}

        <label className="mt-3 flex items-center gap-2 text-sm text-fg-muted">
          <input
            type="checkbox"
            checked={interactive}
            onChange={(e) => setInteractive(e.target.checked)}
          />
          Pause to pick a rule class after the scan
        </label>

        <div className="mt-4 flex justify-end gap-2">
          <Button variant="ghost" onClick={onCancel}>
            Cancel
          </Button>
          <Button
            onClick={() => onStart({ rule_set_ids: selected, interactive })}
            disabled={pending || selected.length === 0}
          >
            Start analysis
          </Button>
        </div>
      </ModalContent>
    </Modal>
  );
}
