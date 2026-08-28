import { useEffect, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { CheckCircle2, XCircle } from "lucide-react";
import { settingsApi, type TestConnectionResult } from "@/lib/adminApi";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { useToast } from "@/components/ui/toast";

export function SettingsPage() {
  const toast = useToast();
  const qc = useQueryClient();
  const { data, isLoading } = useQuery({ queryKey: ["settings"], queryFn: settingsApi.get });

  const [endpoint, setEndpoint] = useState("");
  const [model, setModel] = useState("");
  const [triageModel, setTriageModel] = useState("");
  const [triageEndpoint, setTriageEndpoint] = useState("");
  const [triageProbe, setTriageProbe] = useState<TestConnectionResult | null>(null);
  const [semgrep, setSemgrep] = useState("");
  const [semgrepError, setSemgrepError] = useState<string | null>(null);
  const [probe, setProbe] = useState<TestConnectionResult | null>(null);

  useEffect(() => {
    if (data) {
      setEndpoint(data.llm_endpoint_url ?? "");
      setModel(data.default_model ?? "");
      setTriageModel(data.triage_model ?? "");
      setTriageEndpoint(data.triage_endpoint_url ?? "");
      setSemgrep(data.semgrep_config ? JSON.stringify(data.semgrep_config, null, 2) : "");
    }
  }, [data]);

  const save = useMutation({
    mutationFn: () => {
      let semgrep_config: Record<string, unknown> | null = null;
      if (semgrep.trim()) semgrep_config = JSON.parse(semgrep) as Record<string, unknown>;
      return settingsApi.update({
        llm_endpoint_url: endpoint || null,
        default_model: model || null,
        triage_model: triageModel || null,
        triage_endpoint_url: triageEndpoint || null,
        semgrep_config,
      });
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["settings"] });
      toast({ title: "Settings saved", variant: "success" });
    },
    onError: () => toast({ title: "Could not save settings", variant: "error" }),
  });

  const test = useMutation({
    mutationFn: () => settingsApi.testConnection(endpoint || undefined),
    onSuccess: (res) => setProbe(res),
    onError: () => setProbe({ ok: false, error: "request_failed" }),
  });

  const testTriage = useMutation({
    mutationFn: () => settingsApi.testConnection(triageEndpoint || undefined, "triage"),
    onSuccess: (res) => setTriageProbe(res),
    onError: () => setTriageProbe({ ok: false, error: "request_failed" }),
  });

  function onSave(e: React.FormEvent) {
    e.preventDefault();
    setSemgrepError(null);
    if (semgrep.trim()) {
      try {
        JSON.parse(semgrep);
      } catch {
        setSemgrepError("Semgrep config must be valid JSON.");
        return;
      }
    }
    save.mutate();
  }

  if (isLoading) return <Skeleton className="h-80 w-full" />;

  return (
    <div className="flex max-w-2xl flex-col gap-6">
      <div>
        <h1 className="text-2xl font-bold text-fg">System settings</h1>
        <p className="mt-1 text-fg-muted">
          The LLM endpoint and default model used across Keystone.
        </p>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Language model</CardTitle>
          <CardDescription>
            OpenAI-compatible endpoint. The API key is a deployment secret and is set via
            environment, not here.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <form className="flex flex-col gap-4" onSubmit={onSave}>
            <div className="flex flex-col gap-1.5">
              <Label htmlFor="s-endpoint">LLM endpoint URL</Label>
              <Input
                id="s-endpoint"
                value={endpoint}
                placeholder="https://llm.example.com/api"
                onChange={(e) => setEndpoint(e.target.value)}
              />
            </div>
            <div className="flex flex-col gap-1.5">
              <Label htmlFor="s-model">Default model</Label>
              <Input
                id="s-model"
                value={model}
                placeholder="qwen/qwen3-8b"
                onChange={(e) => setModel(e.target.value)}
              />
            </div>
            <div className="flex items-center gap-3">
              <span className="text-sm text-fg-muted">Deployment key:</span>
              {data?.llm_key_configured ? (
                <Badge variant="good">configured</Badge>
              ) : (
                <Badge variant="warn">not set</Badge>
              )}
            </div>

            <div className="flex flex-col gap-3 rounded-lg border border-border bg-panel-2/40 p-4">
              <div>
                <p className="text-sm font-semibold text-fg">Triage model (optional)</p>
                <p className="text-xs text-fg-muted">
                  A cheaper model for the high-volume VR triage step. Leave blank to reuse the
                  analysis model (endpoint and key fall back to the analysis ones too).
                </p>
              </div>
              <div className="flex flex-col gap-1.5">
                <Label htmlFor="s-triage-model">Triage model</Label>
                <Input
                  id="s-triage-model"
                  value={triageModel}
                  placeholder="(reuse default model)"
                  onChange={(e) => setTriageModel(e.target.value)}
                />
              </div>
              <div className="flex flex-col gap-1.5">
                <Label htmlFor="s-triage-endpoint">Triage endpoint URL (optional)</Label>
                <Input
                  id="s-triage-endpoint"
                  value={triageEndpoint}
                  placeholder="(reuse analysis endpoint)"
                  onChange={(e) => setTriageEndpoint(e.target.value)}
                />
              </div>
              <div className="flex items-center gap-3">
                <span className="text-sm text-fg-muted">Triage key:</span>
                {data?.triage_key_configured ? (
                  <Badge variant="good">available</Badge>
                ) : (
                  <Badge variant="warn">not set</Badge>
                )}
                <Button
                  type="button"
                  variant="ghost"
                  size="sm"
                  disabled={testTriage.isPending}
                  onClick={() => testTriage.mutate()}
                >
                  {testTriage.isPending ? "Testing…" : "Test triage connection"}
                </Button>
              </div>
              {triageProbe && (
                <div
                  role="status"
                  className={`flex items-center gap-2 rounded-lg px-3 py-2 text-sm ${
                    triageProbe.ok ? "bg-good/10 text-good" : "bg-critical/10 text-critical"
                  }`}
                >
                  {triageProbe.ok ? (
                    <>
                      <CheckCircle2 className="h-4 w-4" />
                      Connected{triageProbe.models?.length ? ` — ${triageProbe.models.length} models` : ""}
                    </>
                  ) : (
                    <>
                      <XCircle className="h-4 w-4" />
                      Failed: {triageProbe.error}
                    </>
                  )}
                </div>
              )}
            </div>

            <div className="flex flex-col gap-1.5">
              <Label htmlFor="s-semgrep">Semgrep config (JSON)</Label>
              <textarea
                id="s-semgrep"
                value={semgrep}
                onChange={(e) => setSemgrep(e.target.value)}
                rows={5}
                spellCheck={false}
                className="w-full rounded-lg border border-border bg-panel-2 p-3 font-mono text-sm text-fg focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-amber"
                placeholder='{ "rules": "p/ci" }'
              />
              {semgrepError && <span className="text-xs text-critical">{semgrepError}</span>}
            </div>

            <div className="flex items-center gap-2">
              <Button type="submit" disabled={save.isPending}>
                {save.isPending ? "Saving…" : "Save settings"}
              </Button>
              <Button
                type="button"
                variant="secondary"
                disabled={test.isPending}
                onClick={() => test.mutate()}
              >
                {test.isPending ? "Testing…" : "Test connection"}
              </Button>
            </div>

            {probe && (
              <div
                role="status"
                className={`flex items-center gap-2 rounded-lg px-3 py-2 text-sm ${
                  probe.ok ? "bg-good/10 text-good" : "bg-critical/10 text-critical"
                }`}
              >
                {probe.ok ? (
                  <>
                    <CheckCircle2 className="h-4 w-4" />
                    Connected{probe.models?.length ? ` — ${probe.models.length} models available` : ""}
                  </>
                ) : (
                  <>
                    <XCircle className="h-4 w-4" />
                    Failed: {probe.error}
                  </>
                )}
              </div>
            )}
          </form>
        </CardContent>
      </Card>
    </div>
  );
}
