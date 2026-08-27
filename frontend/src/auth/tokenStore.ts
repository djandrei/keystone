/** Access token lives in memory only; the rotating refresh token persists in
 *  localStorage so a page reload can silently restore the session.
 *  (Refresh-in-cookie is an M5 hardening item — see docs.) */
let accessToken: string | null = null;
export const REFRESH_KEY = "kst_refresh";

export function getAccess(): string | null {
  return accessToken;
}
export function setAccess(token: string | null): void {
  accessToken = token;
}
export function getRefresh(): string | null {
  try {
    return localStorage.getItem(REFRESH_KEY);
  } catch {
    return null;
  }
}
export function setRefresh(token: string | null): void {
  try {
    if (token) localStorage.setItem(REFRESH_KEY, token);
    else localStorage.removeItem(REFRESH_KEY);
  } catch {
    /* storage unavailable — session stays in-memory only */
  }
}
export function clearTokens(): void {
  accessToken = null;
  setRefresh(null);
}
