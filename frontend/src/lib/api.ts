import axios from "axios";
import {
  clearTokens,
  getAccess,
  getRefresh,
  setAccess,
  setRefresh,
} from "@/auth/tokenStore";

export type Role = "admin" | "analyst" | "viewer";

export interface AuthUser {
  id: number;
  username: string;
  email: string;
  role: Role;
}
interface SessionResponse {
  access_token: string;
  refresh_token: string;
  user: AuthUser;
}

export const api = axios.create({ baseURL: "/api" });

api.interceptors.request.use((config) => {
  const token = getAccess();
  if (token) config.headers.Authorization = `Bearer ${token}`;
  return config;
});

/** Rotate the refresh token for a fresh access token; returns the current user.
 *  Uses a bare axios call so it never re-enters the 401 interceptor. */
export async function refreshSession(): Promise<AuthUser> {
  const refresh = getRefresh();
  if (!refresh) throw new Error("no_refresh_token");
  const { data } = await axios.post<SessionResponse>("/api/auth/refresh", {
    refresh_token: refresh,
  });
  setAccess(data.access_token);
  setRefresh(data.refresh_token);
  return data.user;
}

// Single-flight: concurrent 401s share one refresh round-trip.
let inFlight: Promise<AuthUser> | null = null;

api.interceptors.response.use(
  (res) => res,
  async (error) => {
    const original = error.config;
    const status = error.response?.status;
    if (status === 401 && original && !original._retry && getRefresh()) {
      original._retry = true;
      try {
        inFlight = inFlight ?? refreshSession().finally(() => (inFlight = null));
        await inFlight;
        original.headers = original.headers ?? {};
        original.headers.Authorization = `Bearer ${getAccess()}`;
        return api(original);
      } catch {
        clearTokens();
        window.dispatchEvent(new Event("kst:logout"));
      }
    }
    return Promise.reject(error);
  },
);

export const authApi = {
  login: (username: string, password: string) =>
    api.post<SessionResponse>("/auth/login", { username, password }).then((r) => r.data),
  me: () => api.get<AuthUser & { teams: number[] }>("/auth/me").then((r) => r.data),
  logout: (refresh_token: string | null) =>
    api.post("/auth/logout", { refresh_token }).then((r) => r.data),
};
