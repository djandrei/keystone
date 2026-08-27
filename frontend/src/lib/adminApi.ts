import { api, type Role } from "./api";

export interface AdminUser {
  id: number;
  username: string;
  email: string;
  role: Role;
  is_active: boolean;
  created_at: string | null;
  last_login_at: string | null;
}
export interface CreatedUser extends AdminUser {
  temp_password?: string;
}

export interface Team {
  id: number;
  name: string;
  created_at: string | null;
  created_by: number | null;
}
export interface TeamMember {
  user_id: number;
  username: string;
  team_role: "lead" | "member";
  added_at: string | null;
}
export interface TeamDetail extends Team {
  members: TeamMember[];
}

export interface SystemSettings {
  llm_endpoint_url: string | null;
  default_model: string | null;
  semgrep_config: Record<string, unknown> | null;
  updated_by: number | null;
  updated_at: string | null;
  llm_key_configured: boolean;
}
export interface TestConnectionResult {
  ok: boolean;
  models?: string[];
  error?: string;
}

export const usersApi = {
  list: () => api.get<AdminUser[]>("/users").then((r) => r.data),
  create: (body: { username: string; email: string; role: Role; password?: string }) =>
    api.post<CreatedUser>("/users", body).then((r) => r.data),
  update: (id: number, body: { role?: Role; is_active?: boolean; password?: string }) =>
    api.patch<AdminUser>(`/users/${id}`, body).then((r) => r.data),
  deactivate: (id: number) => api.delete(`/users/${id}`).then((r) => r.data),
};

export const teamsApi = {
  list: () => api.get<Team[]>("/teams").then((r) => r.data),
  create: (name: string) => api.post<Team>("/teams", { name }).then((r) => r.data),
  get: (id: number) => api.get<TeamDetail>(`/teams/${id}`).then((r) => r.data),
  addMember: (id: number, user_id: number, team_role: "lead" | "member" = "member") =>
    api.post(`/teams/${id}/members`, { user_id, team_role }).then((r) => r.data),
  removeMember: (id: number, user_id: number) =>
    api.delete(`/teams/${id}/members/${user_id}`).then((r) => r.data),
};

export const settingsApi = {
  get: () => api.get<SystemSettings>("/settings").then((r) => r.data),
  update: (body: Partial<Pick<SystemSettings, "llm_endpoint_url" | "default_model" | "semgrep_config">>) =>
    api.put<SystemSettings>("/settings", body).then((r) => r.data),
  testConnection: (llm_endpoint_url?: string) =>
    api.post<TestConnectionResult>("/settings/test-connection", { llm_endpoint_url }).then((r) => r.data),
};
