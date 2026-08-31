import { useState } from "react";
import { isAxiosError } from "axios";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Check, Pencil, X } from "lucide-react";
import { functionsApi, type FunctionRow } from "@/lib/functionsApi";
import { useAuth } from "@/auth/AuthContext";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { useToast } from "@/components/ui/toast";

function errDetail(err: unknown): string | undefined {
  if (!isAxiosError(err)) return undefined;
  const d = err.response?.data as { error?: string; detail?: string } | undefined;
  if (d?.error === "invalid_name") return "a name must be a plain identifier (letters, digits, _)";
  return d?.detail;
}

/**
 * The functions a run decompiled, with model-suggested names, and a checkbox per
 * function deciding whether it appears in the report.
 *
 * The original Ghidra symbol is always visible beside the friendly name, never
 * behind a hover: a suggested name comes from a model reading attacker-controlled
 * code, so it is a reading aid, not the identity.
 */
export function FunctionsPanel({ analysisId }: { analysisId: number }) {
  const toast = useToast();
  const qc = useQueryClient();
  const { user } = useAuth();
  const canEdit = user?.role === "admin" || user?.role === "analyst";
  const [editing, setEditing] = useState<number | null>(null);
  const [draft, setDraft] = useState("");

  const { data: rows, isLoading } = useQuery({
    queryKey: ["functions", analysisId],
    queryFn: () => functionsApi.list(analysisId),
  });

  // The report composes the section at read time, so refetching it is the whole
  // "update report" flow — there is nothing to regenerate.
  const refresh = () => {
    qc.invalidateQueries({ queryKey: ["functions", analysisId] });
    qc.invalidateQueries({ queryKey: ["report", analysisId] });
  };

  const toggle = useMutation({
    mutationFn: (fn: FunctionRow) =>
      functionsApi.toggle(analysisId, fn.included ? { exclude: [fn.id] } : { include: [fn.id] }),
    onSuccess: refresh,
    onError: (e) => toast({ title: "Could not update", description: errDetail(e), variant: "error" }),
  });

  const rename = useMutation({
    mutationFn: ({ id, name }: { id: number; name: string }) =>
      functionsApi.rename(id, { suggested_name: name }),
    onSuccess: () => {
      setEditing(null);
      refresh();
    },
    onError: (e) => toast({ title: "Could not rename", description: errDetail(e), variant: "error" }),
  });

  if (isLoading) return <Skeleton className="h-32 w-full" />;
  if (!rows?.length) return null;

  return (
    <Card>
      <CardHeader>
        <CardTitle>Functions ({rows.length})</CardTitle>
        <CardDescription>
          Names suggested by the model from the decompiled code. Untick a function to keep it out
          of the report — the Ghidra symbol is shown beside every name.
        </CardDescription>
      </CardHeader>
      <CardContent className="flex flex-col gap-1">
        {rows.map((fn) => (
          <div key={fn.id} className="flex items-start gap-2 rounded-lg p-2 hover:bg-panel-2">
            <input
              type="checkbox"
              className="mt-1"
              checked={fn.included}
              disabled={!canEdit || toggle.isPending}
              aria-label={`Include ${fn.display_name} in the report`}
              onChange={() => toggle.mutate(fn)}
            />
            <div className="min-w-0 flex-1">
              {editing === fn.id ? (
                <div className="flex items-center gap-2">
                  <Input
                    value={draft}
                    aria-label={`New name for ${fn.original_name}`}
                    onChange={(e) => setDraft(e.target.value)}
                    className="h-8 max-w-xs font-mono text-xs"
                  />
                  <Button
                    size="sm"
                    aria-label={`Save name for ${fn.original_name}`}
                    onClick={() => rename.mutate({ id: fn.id, name: draft })}
                  >
                    <Check className="h-3.5 w-3.5" />
                  </Button>
                  <Button
                    size="sm"
                    variant="ghost"
                    aria-label="Cancel rename"
                    onClick={() => setEditing(null)}
                  >
                    <X className="h-3.5 w-3.5" />
                  </Button>
                </div>
              ) : (
                <div className="flex flex-wrap items-center gap-2">
                  <span className="font-mono text-sm text-fg">{fn.display_name}</span>
                  {/* the identity, always visible */}
                  <span className="font-mono text-xs text-fg-muted">
                    {fn.original_name} @ {fn.address}
                  </span>
                  {fn.source === "user" && <Badge variant="default">edited</Badge>}
                  {canEdit && (
                    <Button
                      size="sm"
                      variant="ghost"
                      aria-label={`Rename ${fn.original_name}`}
                      onClick={() => {
                        setEditing(fn.id);
                        setDraft(fn.suggested_name ?? "");
                      }}
                    >
                      <Pencil className="h-3.5 w-3.5" />
                    </Button>
                  )}
                </div>
              )}
              {fn.purpose && <p className="mt-0.5 text-xs text-fg-muted">{fn.purpose}</p>}
            </div>
          </div>
        ))}
      </CardContent>
    </Card>
  );
}
