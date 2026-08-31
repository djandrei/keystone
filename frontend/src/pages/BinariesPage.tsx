import { useMemo, useState } from "react";
import { isAxiosError } from "axios";
import { useNavigate } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { ChevronDown, ChevronRight, FolderPlus, Pencil, Trash2 } from "lucide-react";
import { binariesApi, analysesApi, projectsApi, type BinaryRow, type ProjectRow } from "@/lib/analysisApi";
import { formatBytes } from "@/lib/formatBytes";
import { teamsApi } from "@/lib/adminApi";
import { useTeam } from "@/team/TeamContext";
import { SharedWithCard } from "@/components/SharedWithCard";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Table, TBody, TD, TH, THead, TR } from "@/components/ui/table";
import { Skeleton } from "@/components/ui/skeleton";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { useToast } from "@/components/ui/toast";
import { UploadDropzone } from "@/components/analysis/UploadDropzone";
import { RuleSetPicker, type VrStartOptions } from "@/components/analysis/RuleSetPicker";
import { settingsApi } from "@/lib/adminApi";

function errDetail(err: unknown): string | undefined {
  if (!isAxiosError(err)) return undefined;
  const data = err.response?.data as { error?: string; detail?: string; binaries?: number } | undefined;
  if (data?.error === "has_binaries") return `has ${data.binaries} binaries — move them out first`;
  if (data?.error === "name_taken") return "a project with that name already exists";
  return data?.detail;
}

export function BinariesPage() {
  const toast = useToast();
  const qc = useQueryClient();
  const navigate = useNavigate();
  const { data: teams } = useQuery({ queryKey: ["teams"], queryFn: teamsApi.list });
  const { activeTeamId } = useTeam();
  const [teamId, setTeamId] = useState<string>("");
  const effectiveTeam = teamId || (activeTeamId ? String(activeTeamId) : teams && teams[0] ? String(teams[0].id) : "");
  const teamNum = effectiveTeam ? Number(effectiveTeam) : null;

  const { data: binaries, isLoading } = useQuery({
    queryKey: ["binaries", teamNum],
    queryFn: () => binariesApi.list(teamNum!),
    enabled: teamNum != null,
  });
  const { data: projects } = useQuery({
    queryKey: ["projects", teamNum],
    queryFn: () => projectsApi.list(teamNum!),
    enabled: teamNum != null,
  });
  const { data: team } = useQuery({
    queryKey: ["team", teamNum],
    queryFn: () => teamsApi.get(teamNum!),
    enabled: teamNum != null,
  });
  const memberCount = team?.members.length ?? 0;

  const [uploadProject, setUploadProject] = useState<string>("");
  const [newProject, setNewProject] = useState("");

  const defaultProjectId = projects?.find((p) => p.is_default)?.id;
  const uploadProjectId = uploadProject ? Number(uploadProject) : defaultProjectId;

  const invalidate = () => {
    qc.invalidateQueries({ queryKey: ["binaries"] });
    qc.invalidateQueries({ queryKey: ["projects"] });
  };

  const upload = useMutation({
    mutationFn: (file: File) => binariesApi.upload(Number(effectiveTeam), file, uploadProjectId),
    onSuccess: (b) => {
      invalidate();
      toast({ title: `Uploaded ${b.filename}`, description: `${b.project_name ?? ""}`.trim() || undefined, variant: "success" });
    },
    onError: (err) => toast({ title: "Upload failed", description: errDetail(err), variant: "error" }),
  });

  const createProject = useMutation({
    mutationFn: (name: string) => projectsApi.create(teamNum!, name),
    onSuccess: () => { setNewProject(""); qc.invalidateQueries({ queryKey: ["projects"] }); },
    onError: (err) => toast({ title: "Could not create project", description: errDetail(err), variant: "error" }),
  });

  const renameProject = useMutation({
    mutationFn: ({ id, name }: { id: number; name: string }) => projectsApi.rename(id, name),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["projects"] }),
    onError: (err) => toast({ title: "Could not rename project", description: errDetail(err), variant: "error" }),
  });

  const deleteProject = useMutation({
    mutationFn: (id: number) => projectsApi.remove(id),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["projects"] }),
    onError: (err) => toast({ title: "Could not delete project", description: errDetail(err), variant: "error" }),
  });

  const move = useMutation({
    mutationFn: ({ binaryId, projectId }: { binaryId: number; projectId: number }) => binariesApi.move(binaryId, projectId),
    onSuccess: (b) => { invalidate(); toast({ title: `Moved to ${b.project_name}`, variant: "success" }); },
    onError: () => toast({ title: "Could not move binary", variant: "error" }),
  });

  // VR asks which rule sets to scan with before it starts; RE runs no Semgrep and
  // goes straight through.
  const [vrFor, setVrFor] = useState<number | null>(null);
  const { data: settings } = useQuery({
    queryKey: ["settings"],
    queryFn: settingsApi.get,
    retry: false,
  });

  const start = useMutation({
    mutationFn: ({ binaryId, mode, params }: { binaryId: number; mode: "re" | "vr"; params?: Record<string, unknown> }) =>
      analysesApi.start(binaryId, mode, params),
    onSuccess: (a) => { setVrFor(null); qc.invalidateQueries({ queryKey: ["analyses"] }); navigate(`/analyses/${a.id}`); },
    onError: (err) => toast({ title: "Could not start analysis", description: errDetail(err), variant: "error" }),
  });

  const byProject = useMemo(() => {
    const m = new Map<number, BinaryRow[]>();
    for (const b of binaries ?? []) {
      const list = m.get(b.project_id) ?? [];
      list.push(b);
      m.set(b.project_id, list);
    }
    return m;
  }, [binaries]);

  return (
    <div className="flex flex-col gap-6">
      <div>
        <h1 className="text-2xl font-bold text-fg">Binaries</h1>
        <p className="mt-1 text-fg-muted">Upload a binary into a project, then run an analysis. Samples are never executed.</p>
      </div>

      <SharedWithCard teamId={teamNum} />

      <Card>
        <CardHeader>
          <CardTitle>Upload</CardTitle>
        </CardHeader>
        <CardContent className="flex flex-col gap-4">
          <div className="flex flex-wrap gap-4">
            <div className="flex min-w-48 flex-col gap-1.5">
              <Label>Team</Label>
              <Select value={effectiveTeam} onValueChange={(v) => { setTeamId(v); setUploadProject(""); }}>
                <SelectTrigger aria-label="Team"><SelectValue placeholder="Select a team…" /></SelectTrigger>
                <SelectContent>
                  {teams?.map((t) => <SelectItem key={t.id} value={String(t.id)}>{t.name}</SelectItem>)}
                </SelectContent>
              </Select>
            </div>
            <div className="flex min-w-48 flex-col gap-1.5">
              <Label>Project</Label>
              <Select value={uploadProjectId ? String(uploadProjectId) : ""} onValueChange={setUploadProject}>
                <SelectTrigger aria-label="Project"><SelectValue placeholder="Unassigned" /></SelectTrigger>
                <SelectContent>
                  {projects?.map((p) => <SelectItem key={p.id} value={String(p.id)}>{p.name}</SelectItem>)}
                </SelectContent>
              </Select>
            </div>
          </div>
          <UploadDropzone onFile={(f) => upload.mutate(f)} disabled={!effectiveTeam || upload.isPending} />
        </CardContent>
      </Card>

      <div className="flex items-end gap-2">
        <div className="flex flex-col gap-1.5">
          <Label htmlFor="new-project">New project</Label>
          <Input
            id="new-project"
            className="w-56"
            placeholder="e.g. firmware-x"
            value={newProject}
            onChange={(e) => setNewProject(e.target.value)}
            onKeyDown={(e) => { if (e.key === "Enter" && newProject.trim()) createProject.mutate(newProject.trim()); }}
          />
        </div>
        <Button
          variant="secondary"
          disabled={!newProject.trim() || !teamNum || createProject.isPending}
          onClick={() => createProject.mutate(newProject.trim())}
        >
          <FolderPlus className="h-4 w-4" /> Create
        </Button>
      </div>

      {isLoading ? (
        <Skeleton className="h-40 w-full" />
      ) : (
        <div className="flex flex-col gap-4">
          {projects?.map((p) => (
            <ProjectSection
              key={p.id}
              project={p}
              binaries={byProject.get(p.id) ?? []}
              projects={projects}
              memberCount={memberCount}
              teamName={team?.name}
              onRename={(name) => renameProject.mutate({ id: p.id, name })}
              onDelete={() => deleteProject.mutate(p.id)}
              onMove={(binaryId, projectId) => move.mutate({ binaryId, projectId })}
              onRun={(binaryId, mode) =>
                mode === "vr" ? setVrFor(binaryId) : start.mutate({ binaryId, mode })
              }
              runPending={start.isPending}
            />
          ))}
        </div>
      )}

      <RuleSetPicker
        open={vrFor != null}
        defaultRuleSetId={settings?.default_rule_set_id ?? null}
        pending={start.isPending}
        onCancel={() => setVrFor(null)}
        onStart={(opts: VrStartOptions) =>
          start.mutate({ binaryId: vrFor!, mode: "vr", params: { ...opts } })
        }
      />
    </div>
  );
}

function ProjectSection({
  project, binaries, projects, memberCount, teamName, onRename, onDelete, onMove, onRun, runPending,
}: {
  project: ProjectRow;
  binaries: BinaryRow[];
  projects: ProjectRow[];
  memberCount: number;
  teamName?: string;
  onRename: (name: string) => void;
  onDelete: () => void;
  onMove: (binaryId: number, projectId: number) => void;
  onRun: (binaryId: number, mode: "re" | "vr") => void;
  runPending: boolean;
}) {
  const [open, setOpen] = useState(true);
  const [editing, setEditing] = useState(false);
  const [name, setName] = useState(project.name);

  return (
    <Card>
      <CardHeader className="flex-row items-center justify-between gap-2 space-y-0">
        <button className="flex items-center gap-2" onClick={() => setOpen((o) => !o)} aria-label={`Toggle ${project.name}`}>
          {open ? <ChevronDown className="h-4 w-4" /> : <ChevronRight className="h-4 w-4" />}
          {editing ? (
            <Input
              autoFocus
              className="h-8 w-48"
              value={name}
              onClick={(e) => e.stopPropagation()}
              onChange={(e) => setName(e.target.value)}
              onKeyDown={(e) => { if (e.key === "Enter") { onRename(name.trim()); setEditing(false); } if (e.key === "Escape") { setName(project.name); setEditing(false); } }}
            />
          ) : (
            <CardTitle className="text-base">{project.name}</CardTitle>
          )}
          <Badge variant="info">{binaries.length}</Badge>
          {memberCount > 0 && (
            <span
              className="text-xs text-fg-muted"
              title={`Shared with all ${memberCount} member${memberCount === 1 ? "" : "s"}${teamName ? ` of ${teamName}` : ""}`}
            >
              · shared with {memberCount} member{memberCount === 1 ? "" : "s"}
            </span>
          )}
        </button>
        {!project.is_default && !editing && (
          <div className="flex gap-1">
            <Button size="icon" variant="ghost" aria-label={`Rename ${project.name}`} onClick={() => { setName(project.name); setEditing(true); }}>
              <Pencil className="h-4 w-4" />
            </Button>
            <Button size="icon" variant="ghost" aria-label={`Delete ${project.name}`} onClick={onDelete}>
              <Trash2 className="h-4 w-4" />
            </Button>
          </div>
        )}
      </CardHeader>
      {open && (
        <CardContent>
          {binaries.length === 0 ? (
            <p className="text-sm text-fg-muted">No binaries in this project.</p>
          ) : (
            <Table>
              <THead>
                <TR>
                  <TH>Name</TH>
                  <TH>Format</TH>
                  <TH>Arch</TH>
                  <TH className="text-right">Size</TH>
                  <TH>Move to</TH>
                  <TH className="text-right">Action</TH>
                </TR>
              </THead>
              <TBody>
                {binaries.map((b) => (
                  <TR key={b.id}>
                    <TD className="font-medium">{b.filename}</TD>
                    <TD>{b.format && <Badge>{b.format}</Badge>}</TD>
                    <TD className="text-fg-muted">{b.arch ?? "—"}</TD>
                    <TD className="text-right text-fg-muted tabular-nums">{formatBytes(b.size)}</TD>
                    <TD>
                      <Select value={String(b.project_id)} onValueChange={(v) => onMove(b.id, Number(v))}>
                        <SelectTrigger aria-label={`Move ${b.filename}`} className="h-8 w-40"><SelectValue /></SelectTrigger>
                        <SelectContent>
                          {projects.map((p) => <SelectItem key={p.id} value={String(p.id)}>{p.name}</SelectItem>)}
                        </SelectContent>
                      </Select>
                    </TD>
                    <TD>
                      <div className="flex justify-end gap-2">
                        <Button size="sm" disabled={runPending} onClick={() => onRun(b.id, "re")}>Run RE</Button>
                        <Button size="sm" variant="secondary" disabled={runPending} onClick={() => onRun(b.id, "vr")}>Run VR</Button>
                      </div>
                    </TD>
                  </TR>
                ))}
              </TBody>
            </Table>
          )}
        </CardContent>
      )}
    </Card>
  );
}
