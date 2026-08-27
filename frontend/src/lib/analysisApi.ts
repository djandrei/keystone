import { api } from "./api";

export type AnalysisMode = "re" | "vr";
export type AnalysisStatus = "queued" | "running" | "succeeded" | "failed" | "canceled";

export interface BinaryRow {
  id: number;
  team_id: number;
  sha256: string;
  filename: string;
  size: number;
  format: string | null;
  arch: string | null;
  platform: string | null;
  ghidra_program_name: string | null;
  uploaded_by: number;
  created_at: string | null;
}

export interface REResultView {
  binary_type: string | null;
  purpose: string | null;
  key_functions: string | null;
  attack_surface: string | null;
  language_runtime: string | null;
  tool_calls: number | null;
}

export interface ProgressSnapshot {
  events: StreamEvent[];
}

export interface AnalysisRow {
  id: number;
  team_id: number;
  binary_id: number;
  mode: AnalysisMode;
  status: AnalysisStatus;
  model: string | null;
  params: Record<string, unknown> | null;
  created_by: number;
  created_by_username?: string | null;
  created_at: string | null;
  started_at: string | null;
  finished_at: string | null;
  error: string | null;
  progress: ProgressSnapshot | null;
  re_result?: REResultView;
}

export interface VRFindingRow {
  id: number;
  rule: string | null;
  file: string | null;
  line: number | null;
  semgrep_message: string | null;
  classification: "true_positive" | "false_positive" | "needs_review" | null;
  risk_level: "critical" | "high" | "medium" | "low" | "informational" | null;
  cwe_id: string | null;
  reasoning: string | null;
  reachable: string | null;
  entry_path: string | null;
  confidence: string | null;
}

export interface AnalysisPage {
  items: AnalysisRow[];
  total: number;
  limit: number;
  offset: number;
}

export interface StreamEvent {
  type: string;
  seq?: number;
  step?: string;
  message?: string;
  data?: Record<string, unknown> | null;
}

export const binariesApi = {
  list: (teamId?: number) =>
    api.get<BinaryRow[]>("/binaries", { params: teamId ? { team_id: teamId } : {} }).then((r) => r.data),
  upload: (teamId: number, file: File) => {
    const fd = new FormData();
    fd.append("team_id", String(teamId));
    fd.append("file", file);
    return api.post<BinaryRow>("/binaries", fd).then((r) => r.data);
  },
};

export const analysesApi = {
  start: (binaryId: number, mode: AnalysisMode = "re", params?: Record<string, unknown>) =>
    api.post<AnalysisRow>(`/binaries/${binaryId}/analyses`, { mode, params }).then((r) => r.data),
  list: (filters?: Record<string, string | number>) =>
    api.get<AnalysisPage>("/analyses", { params: filters }).then((r) => r.data.items),
  listPage: (filters?: Record<string, string | number>) =>
    api.get<AnalysisPage>("/analyses", { params: filters }).then((r) => r.data),
  get: (id: number) => api.get<AnalysisRow>(`/analyses/${id}`).then((r) => r.data),
  report: (id: number) => api.get<string>(`/analyses/${id}/report`, { responseType: "text" }).then((r) => r.data),
  cancel: (id: number) => api.post(`/analyses/${id}/cancel`).then((r) => r.data),
  findings: (id: number) => api.get<VRFindingRow[]>(`/analyses/${id}/findings`).then((r) => r.data),
  selectRule: (id: number, rule: string) =>
    api.post(`/analyses/${id}/select-rule`, { rule }).then((r) => r.data),
  export: (id: number, format: "md" | "json" | "pdf") =>
    api.get(`/analyses/${id}/export`, { params: { format }, responseType: "blob" }).then((r) => r.data as Blob),
};
