import { useEffect, useMemo, useState } from "react";
import { isAxiosError } from "axios";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { AlertTriangle, Archive, Copy, FileCode2, History, Plus } from "lucide-react";
import { ruleSetsApi, type RuleSetRow, type ValidateResult } from "@/lib/ruleSetsApi";
import { RuleSetCredit } from "@/components/RuleSetCredit";
import { teamsApi } from "@/lib/adminApi";
import { useAuth } from "@/auth/AuthContext";
import { useTeam } from "@/team/TeamContext";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Table, TBody, TD, TH, THead, TR } from "@/components/ui/table";
import { Skeleton } from "@/components/ui/skeleton";
import { Modal, ModalContent, ModalHeader, ModalTitle, ModalDescription } from "@/components/ui/modal";
import { useToast } from "@/components/ui/toast";

const STARTER = `rules:
  - id: my-rule
    languages: [c]
    severity: WARNING
    message: What this rule found, and why it matters.
    patterns:
      - pattern-either:
          - pattern: memcpy(...)
`;

function errDetail(err: unknown): string | undefined {
  if (!isAxiosError(err)) return undefined;
  const d = err.response?.data as
    | { error?: string; detail?: string; errors?: string[]; analyses?: number }
    | undefined;
  if (d?.error === "in_use") return `${d.analyses} analyses ran it — archive it instead`;
  if (d?.error === "name_taken") return "a rule set with that name already exists";
  if (d?.error === "unchanged") return "the content is identical to the latest version";
  if (d?.errors?.length) return d.errors.join("; ");
  return d?.detail;
}

export function RuleSetsPage() {
  const toast = useToast();
  const qc = useQueryClient();
  const { user } = useAuth();
  const { activeTeamId } = useTeam();
  const { data: teams } = useQuery({ queryKey: ["teams"], queryFn: teamsApi.list });
  const teamNum = activeTeamId ?? (teams && teams[0] ? teams[0].id : null);
  const canWrite = user?.role === "admin" || user?.role === "analyst";

  const [search, setSearch] = useState("");
  const [editing, setEditing] = useState<{ id: number | null; name: string } | null>(null);

  const { data: rows, isLoading } = useQuery({
    queryKey: ["rule-sets", search],
    queryFn: () => ruleSetsApi.list(search ? { q: search } : {}),
  });

  const invalidate = () => qc.invalidateQueries({ queryKey: ["rule-sets"] });

  const archive = useMutation({
    mutationFn: (rs: RuleSetRow) => ruleSetsApi.update(rs.id, { archived: !rs.archived }),
    onSuccess: invalidate,
    onError: (e) => toast({ title: "Could not archive", description: errDetail(e), variant: "error" }),
  });

  const clone = useMutation({
    mutationFn: (rs: RuleSetRow) => ruleSetsApi.clone(rs.id, teamNum!, `${rs.name} (copy)`),
    onSuccess: (rs) => {
      invalidate();
      toast({ title: `Cloned into your team as “${rs.name}”`, variant: "success" });
    },
    onError: (e) => toast({ title: "Could not clone", description: errDetail(e), variant: "error" }),
  });

  const builtins = useMemo(() => (rows ?? []).filter((r) => r.is_builtin), [rows]);
  const mine = useMemo(() => (rows ?? []).filter((r) => !r.is_builtin), [rows]);

  return (
    <div className="flex flex-col gap-6">
      <div className="flex items-end justify-between gap-4">
        <div>
          <h1 className="text-2xl font-semibold text-fg">Rule sets</h1>
          <p className="text-sm text-fg-muted">
            Semgrep patterns a VR analysis scans decompiled code with. Built-ins ship with
            Keystone — clone one to customize it for your team.
          </p>
        </div>
        {canWrite && (
          <Button onClick={() => setEditing({ id: null, name: "" })}>
            <Plus className="mr-1 h-4 w-4" /> New rule set
          </Button>
        )}
      </div>

      <Input
        placeholder="Search rule sets…"
        value={search}
        onChange={(e) => setSearch(e.target.value)}
        aria-label="Search rule sets"
        className="max-w-sm"
      />

      {isLoading ? (
        <Skeleton className="h-40 w-full" />
      ) : (
        <>
          <RuleSetTable
            title="Built-in rule sets"
            rows={builtins}
            canWrite={canWrite}
            canClone={canWrite && teamNum != null}
            onEdit={(r) => setEditing({ id: r.id, name: r.name })}
            onArchive={(r) => archive.mutate(r)}
            onClone={(r) => clone.mutate(r)}
            isAdmin={user?.role === "admin"}
          />
          <RuleSetTable
            title="Your teams"
            rows={mine}
            canWrite={canWrite}
            canClone={canWrite && teamNum != null}
            onEdit={(r) => setEditing({ id: r.id, name: r.name })}
            onArchive={(r) => archive.mutate(r)}
            onClone={(r) => clone.mutate(r)}
            isAdmin={user?.role === "admin"}
          />
        </>
      )}

      {editing && (
        <EditorModal
          ruleSetId={editing.id}
          teamId={teamNum}
          onClose={() => setEditing(null)}
          onSaved={() => {
            setEditing(null);
            invalidate();
          }}
        />
      )}
    </div>
  );
}

function RuleSetTable({
  title,
  rows,
  canWrite,
  canClone,
  isAdmin,
  onEdit,
  onArchive,
  onClone,
}: {
  title: string;
  rows: RuleSetRow[];
  canWrite: boolean;
  canClone: boolean;
  isAdmin: boolean;
  onEdit: (r: RuleSetRow) => void;
  onArchive: (r: RuleSetRow) => void;
  onClone: (r: RuleSetRow) => void;
}) {
  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-base">{title}</CardTitle>
      </CardHeader>
      <CardContent>
        {rows.length === 0 ? (
          <p className="text-sm text-fg-muted">Nothing here yet.</p>
        ) : (
          <Table>
            <THead>
              <TR>
                <TH>Name</TH>
                <TH>Languages</TH>
                <TH>Rules</TH>
                <TH>Version</TH>
                <TH className="text-right">Actions</TH>
              </TR>
            </THead>
            <TBody>
              {rows.map((r) => {
                // A built-in is admin-only to edit; that's what `clone` is for.
                const editable = canWrite && (!r.is_builtin || isAdmin);
                return (
                  <TR key={r.id}>
                    <TD>
                      <div className="flex items-center gap-2">
                        <FileCode2 className="h-4 w-4 text-fg-muted" />
                        <span className="font-medium text-fg">{r.name}</span>
                        {r.is_builtin && <Badge variant="default">Built-in</Badge>}
                        {r.archived && <Badge variant="default">Archived</Badge>}
                        {r.latest_version?.security?.suspected && (
                          <span title="A rule message looks like prompt injection" className="text-amber">
                            <AlertTriangle className="h-4 w-4" aria-label="Flagged rule text" />
                          </span>
                        )}
                      </div>
                      {r.description && (
                        <p className="mt-0.5 text-xs text-fg-muted">{r.description}</p>
                      )}
                      <RuleSetCredit attribution={r.attribution} className="mt-0.5" />
                    </TD>
                    <TD className="text-fg-muted">{r.languages.join(", ") || "—"}</TD>
                    <TD className="text-fg-muted">{r.latest_version?.rule_count ?? 0}</TD>
                    <TD className="text-fg-muted">
                      {r.latest_version ? `v${r.latest_version.version_no}` : "—"}
                    </TD>
                    <TD className="text-right">
                      <div className="flex justify-end gap-2">
                        <Button size="sm" variant="ghost" onClick={() => onEdit(r)}>
                          <History className="mr-1 h-3.5 w-3.5" />
                          {editable ? "Edit" : "View"}
                        </Button>
                        {canClone && (
                          <Button size="sm" variant="ghost" onClick={() => onClone(r)}>
                            <Copy className="mr-1 h-3.5 w-3.5" /> Clone
                          </Button>
                        )}
                        {editable && (
                          <Button size="sm" variant="ghost" onClick={() => onArchive(r)}>
                            <Archive className="mr-1 h-3.5 w-3.5" />
                            {r.archived ? "Restore" : "Archive"}
                          </Button>
                        )}
                      </div>
                    </TD>
                  </TR>
                );
              })}
            </TBody>
          </Table>
        )}
      </CardContent>
    </Card>
  );
}

function EditorModal({
  ruleSetId,
  teamId,
  onClose,
  onSaved,
}: {
  ruleSetId: number | null;
  teamId: number | null;
  onClose: () => void;
  onSaved: () => void;
}) {
  const toast = useToast();
  const { user } = useAuth();
  const isNew = ruleSetId == null;

  const { data: detail } = useQuery({
    queryKey: ["rule-set", ruleSetId],
    queryFn: () => ruleSetsApi.get(ruleSetId!),
    enabled: !isNew,
  });

  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [content, setContent] = useState(STARTER);
  const [notes, setNotes] = useState("");
  const [probe, setProbe] = useState<ValidateResult | null>(null);

  useEffect(() => {
    if (detail) {
      setName(detail.name);
      setDescription(detail.description ?? "");
      setContent(detail.content ?? "");
    }
  }, [detail]);

  const readOnly = !isNew && detail?.is_builtin === true && user?.role !== "admin";

  const validate = useMutation({
    mutationFn: () => ruleSetsApi.validate(content),
    onSuccess: setProbe,
    onError: () => setProbe({ ok: false, errors: ["could not reach the validator"] }),
  });

  const save = useMutation<unknown>({
    mutationFn: () =>
      isNew
        ? ruleSetsApi.create({ team_id: teamId, name, description, content })
        : ruleSetsApi.addVersion(ruleSetId!, content, notes || undefined),
    onSuccess: () => {
      toast({ title: isNew ? "Rule set created" : "New version saved", variant: "success" });
      onSaved();
    },
    onError: (e) =>
      toast({ title: "Could not save", description: errDetail(e), variant: "error" }),
  });

  return (
    <Modal open onOpenChange={(o) => !o && onClose()}>
      <ModalContent className="max-w-3xl">
        <ModalHeader>
          <ModalTitle>{isNew ? "New rule set" : detail?.name ?? "Rule set"}</ModalTitle>
          <ModalDescription>
            {isNew
              ? "Semgrep YAML. It is validated before it is stored."
              : "Saving appends a new version — earlier versions are never rewritten, so past analyses stay explainable."}
          </ModalDescription>
        </ModalHeader>

        {detail?.attribution && (
          <RuleSetCredit
            attribution={detail.attribution}
            className="-mt-2 mb-3 border-l-2 border-border pl-3"
          />
        )}

        <div className="flex flex-col gap-3">
          {isNew && (
            <>
              <div>
                <Label htmlFor="rs-name">Name</Label>
                <Input id="rs-name" value={name} onChange={(e) => setName(e.target.value)} />
              </div>
              <div>
                <Label htmlFor="rs-desc">Description</Label>
                <Input
                  id="rs-desc"
                  value={description}
                  onChange={(e) => setDescription(e.target.value)}
                />
              </div>
            </>
          )}

          <div>
            <Label htmlFor="rs-content">Rules (YAML)</Label>
            <textarea
              id="rs-content"
              value={content}
              readOnly={readOnly}
              onChange={(e) => setContent(e.target.value)}
              spellCheck={false}
              rows={16}
              className="w-full rounded-lg border border-border bg-bg p-3 font-mono text-xs text-fg focus-visible:ring-2 focus-visible:ring-amber"
            />
          </div>

          {!isNew && !readOnly && (
            <div>
              <Label htmlFor="rs-notes">What changed?</Label>
              <Input id="rs-notes" value={notes} onChange={(e) => setNotes(e.target.value)} />
            </div>
          )}

          {probe && (
            <div
              role="status"
              className={`rounded-lg border p-3 text-xs ${probe.ok ? "border-border text-fg-muted" : "border-critical text-critical"}`}
            >
              {probe.ok ? (
                <>
                  Valid — {probe.rule_ids?.length ?? 0} rules: {(probe.rule_ids ?? []).join(", ")}
                  {probe.security?.suspected && (
                    <p className="mt-1 text-amber">
                      ⚠ A rule message looks like prompt injection. It is fenced before it reaches
                      the triage model, but check it is what you meant.
                    </p>
                  )}
                </>
              ) : (
                <ul className="list-inside list-disc">
                  {probe.errors.map((e) => (
                    <li key={e}>{e}</li>
                  ))}
                </ul>
              )}
            </div>
          )}

          {detail && detail.versions.length > 0 && (
            <details className="text-xs text-fg-muted">
              <summary className="cursor-pointer">Version history ({detail.versions.length})</summary>
              <ul className="mt-2 flex flex-col gap-1">
                {detail.versions.map((v) => (
                  <li key={v.id}>
                    <span className="font-medium text-fg">v{v.version_no}</span> · {v.rule_count}{" "}
                    rules · {v.created_at?.slice(0, 10) ?? ""} {v.notes ? `· ${v.notes}` : ""}
                  </li>
                ))}
              </ul>
            </details>
          )}
        </div>

        <div className="mt-4 flex justify-end gap-2">
          <Button variant="ghost" onClick={onClose}>
            Cancel
          </Button>
          <Button variant="secondary" onClick={() => validate.mutate()} disabled={validate.isPending}>
            Validate
          </Button>
          {!readOnly && (
            <Button onClick={() => save.mutate()} disabled={save.isPending || (isNew && !name)}>
              {isNew ? "Create" : "Save new version"}
            </Button>
          )}
        </div>
      </ModalContent>
    </Modal>
  );
}
