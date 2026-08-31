import { api } from "./api";

/** One immutable revision of a rule set. Content is fetched separately except on
 *  the detail endpoint, which returns the latest inline so the editor opens ready. */
export interface RuleSetVersionRow {
  id: number;
  version_no: number;
  content_sha256: string;
  rule_ids: string[];
  rule_count: number;
  notes: string | null;
  security: { suspected: boolean; evidence?: string[] } | null;
  created_by: number | null;
  created_at: string | null;
  content?: string;
}

/** Who wrote an imported rule set's rules, under what licence, and where from.
 *  Null for rule sets authored in Keystone. Credit is shown wherever the rule set
 *  appears — the licences these ship under ask for it, and it is owed anyway. */
export interface RuleSetAttribution {
  author: string;
  license?: string;
  url?: string;
  commit?: string;
}

export interface RuleSetRow {
  id: number;
  /** null => a system built-in, readable by every team and writable only by admins. */
  team_id: number | null;
  name: string;
  description: string | null;
  languages: string[];
  is_builtin: boolean;
  attribution: RuleSetAttribution | null;
  archived: boolean;
  created_by: number | null;
  created_at: string | null;
  latest_version: RuleSetVersionRow | null;
}

export interface RuleSetDetail extends RuleSetRow {
  versions: RuleSetVersionRow[];
  content?: string;
}

export interface ValidateResult {
  ok: boolean;
  errors: string[];
  rule_ids?: string[];
  languages?: string[];
  security?: { suspected: boolean; evidence?: string[] } | null;
}

export interface ListParams {
  team_id?: number;
  include_builtin?: 0 | 1;
  archived?: 0 | 1;
  q?: string;
}

export const ruleSetsApi = {
  list: (params: ListParams = {}) =>
    api.get<RuleSetRow[]>("/rule-sets", { params }).then((r) => r.data),
  get: (id: number) => api.get<RuleSetDetail>(`/rule-sets/${id}`).then((r) => r.data),
  create: (body: {
    team_id?: number | null;
    name: string;
    description?: string | null;
    languages?: string[];
    content: string;
  }) => api.post<RuleSetRow>("/rule-sets", body).then((r) => r.data),
  update: (id: number, body: { name?: string; description?: string; archived?: boolean }) =>
    api.patch<RuleSetRow>(`/rule-sets/${id}`, body).then((r) => r.data),
  remove: (id: number) => api.delete(`/rule-sets/${id}`).then((r) => r.data),
  addVersion: (id: number, content: string, notes?: string) =>
    api.post<RuleSetVersionRow>(`/rule-sets/${id}/versions`, { content, notes }).then((r) => r.data),
  getVersion: (id: number, versionNo: number) =>
    api.get<RuleSetVersionRow>(`/rule-sets/${id}/versions/${versionNo}`).then((r) => r.data),
  clone: (id: number, teamId: number, name?: string) =>
    api.post<RuleSetRow>(`/rule-sets/${id}/clone`, { team_id: teamId, name }).then((r) => r.data),
  validate: (content: string) =>
    api.post<ValidateResult>("/rule-sets/validate", { content }).then((r) => r.data),
};
