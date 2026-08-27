import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { binariesApi, analysesApi } from "@/lib/analysisApi";
import { teamsApi } from "@/lib/adminApi";
import { Button } from "@/components/ui/button";
import { Label } from "@/components/ui/label";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Table, TBody, TD, TH, THead, TR } from "@/components/ui/table";
import { Skeleton } from "@/components/ui/skeleton";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { useToast } from "@/components/ui/toast";
import { UploadDropzone } from "@/components/analysis/UploadDropzone";

export function BinariesPage() {
  const toast = useToast();
  const qc = useQueryClient();
  const navigate = useNavigate();
  const { data: teams } = useQuery({ queryKey: ["teams"], queryFn: teamsApi.list });
  const [teamId, setTeamId] = useState<string>("");
  const { data: binaries, isLoading } = useQuery({ queryKey: ["binaries"], queryFn: () => binariesApi.list() });

  const effectiveTeam = teamId || (teams && teams[0] ? String(teams[0].id) : "");

  const upload = useMutation({
    mutationFn: (file: File) => binariesApi.upload(Number(effectiveTeam), file),
    onSuccess: (b) => {
      qc.invalidateQueries({ queryKey: ["binaries"] });
      toast({ title: `Uploaded ${b.filename}`, description: `${b.format ?? "?"} · ${b.arch ?? "?"}`, variant: "success" });
    },
    onError: () => toast({ title: "Upload failed", variant: "error" }),
  });

  const start = useMutation({
    mutationFn: ({ binaryId, mode }: { binaryId: number; mode: "re" | "vr" }) =>
      analysesApi.start(binaryId, mode, mode === "vr" ? { interactive: true } : undefined),
    onSuccess: (a) => {
      qc.invalidateQueries({ queryKey: ["analyses"] });
      navigate(`/analyses/${a.id}`);
    },
    onError: () => toast({ title: "Could not start analysis", variant: "error" }),
  });

  return (
    <div className="flex flex-col gap-6">
      <div>
        <h1 className="text-2xl font-bold text-fg">Binaries</h1>
        <p className="mt-1 text-fg-muted">Upload a binary, then run an analysis. Samples are never executed.</p>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Upload</CardTitle>
        </CardHeader>
        <CardContent className="flex flex-col gap-4">
          <div className="flex max-w-xs flex-col gap-1.5">
            <Label>Team</Label>
            <Select value={effectiveTeam} onValueChange={setTeamId}>
              <SelectTrigger aria-label="Team">
                <SelectValue placeholder="Select a team…" />
              </SelectTrigger>
              <SelectContent>
                {teams?.map((t) => (
                  <SelectItem key={t.id} value={String(t.id)}>
                    {t.name}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
          <UploadDropzone onFile={(f) => upload.mutate(f)} disabled={!effectiveTeam || upload.isPending} />
        </CardContent>
      </Card>

      {isLoading ? (
        <Skeleton className="h-40 w-full" />
      ) : (
        <Table>
          <THead>
            <TR>
              <TH>Name</TH>
              <TH>Format</TH>
              <TH>Arch</TH>
              <TH>Platform</TH>
              <TH className="text-right">Action</TH>
            </TR>
          </THead>
          <TBody>
            {binaries?.map((b) => (
              <TR key={b.id}>
                <TD className="font-medium">{b.filename}</TD>
                <TD>{b.format && <Badge>{b.format}</Badge>}</TD>
                <TD className="text-fg-muted">{b.arch ?? "—"}</TD>
                <TD className="text-fg-muted">{b.platform ?? "—"}</TD>
                <TD>
                  <div className="flex justify-end gap-2">
                    <Button size="sm" disabled={start.isPending} onClick={() => start.mutate({ binaryId: b.id, mode: "re" })}>
                      Run RE
                    </Button>
                    <Button size="sm" variant="secondary" disabled={start.isPending} onClick={() => start.mutate({ binaryId: b.id, mode: "vr" })}>
                      Run VR
                    </Button>
                  </div>
                </TD>
              </TR>
            ))}
            {binaries?.length === 0 && (
              <TR>
                <TD colSpan={5} className="text-center text-fg-muted">
                  No binaries yet — upload one above.
                </TD>
              </TR>
            )}
          </TBody>
        </Table>
      )}
    </div>
  );
}
