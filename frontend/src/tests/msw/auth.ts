import { http, HttpResponse } from "msw";
import type { AuthUser } from "@/lib/api";

export const ADMIN: AuthUser = { id: 1, username: "admin", email: "admin@keystone.local", role: "admin" };
export const VIEWER: AuthUser = { id: 2, username: "vic", email: "vic@x.io", role: "viewer" };

/** Login handler: `secret` succeeds, anything else 401s. */
export function loginHandler(user: AuthUser = ADMIN, password = "secret") {
  return http.post("/api/auth/login", async ({ request }) => {
    const body = (await request.json()) as { username: string; password: string };
    if (body.password !== password) {
      return HttpResponse.json({ error: "invalid_credentials" }, { status: 401 });
    }
    return HttpResponse.json({ access_token: "access-1", refresh_token: "refresh-1", user });
  });
}

export function refreshHandler(user: AuthUser = ADMIN) {
  return http.post("/api/auth/refresh", () =>
    HttpResponse.json({ access_token: "access-2", refresh_token: "refresh-2", user }),
  );
}

export function logoutHandler() {
  return http.post("/api/auth/logout", () => HttpResponse.json({ status: "ok" }));
}
