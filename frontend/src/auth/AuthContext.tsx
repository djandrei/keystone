import { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState } from "react";
import {
  authApi,
  refreshSession,
  type AuthUser,
} from "@/lib/api";
import { clearTokens, getRefresh, setAccess, setRefresh } from "./tokenStore";

type Status = "loading" | "authed" | "anon";

interface AuthValue {
  user: AuthUser | null;
  status: Status;
  login: (username: string, password: string) => Promise<void>;
  logout: () => Promise<void>;
}

const AuthContext = createContext<AuthValue | null>(null);

export function useAuth(): AuthValue {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error("useAuth must be used within <AuthProvider>");
  return ctx;
}

/** Non-null current user — only call inside authenticated routes. */
export function useCurrentUser(): AuthUser {
  const { user } = useAuth();
  if (!user) throw new Error("useCurrentUser called outside an authenticated route");
  return user;
}

export function AuthProvider({ children }: { children: React.ReactNode }) {
  const [user, setUser] = useState<AuthUser | null>(null);
  const [status, setStatus] = useState<Status>("loading");
  const booted = useRef(false);

  // Restore a session from a persisted refresh token on first mount.
  useEffect(() => {
    if (booted.current) return;
    booted.current = true;
    (async () => {
      if (!getRefresh()) {
        setStatus("anon");
        return;
      }
      try {
        setUser(await refreshSession());
        setStatus("authed");
      } catch {
        clearTokens();
        setStatus("anon");
      }
    })();
  }, []);

  // The api interceptor fires this when a silent refresh ultimately fails.
  useEffect(() => {
    const onLogout = () => {
      setUser(null);
      setStatus("anon");
    };
    window.addEventListener("kst:logout", onLogout);
    return () => window.removeEventListener("kst:logout", onLogout);
  }, []);

  const login = useCallback(async (username: string, password: string) => {
    const res = await authApi.login(username, password);
    setAccess(res.access_token);
    setRefresh(res.refresh_token);
    setUser(res.user);
    setStatus("authed");
  }, []);

  const logout = useCallback(async () => {
    try {
      await authApi.logout(getRefresh());
    } catch {
      /* best effort */
    } finally {
      clearTokens();
      setUser(null);
      setStatus("anon");
    }
  }, []);

  const value = useMemo(() => ({ user, status, login, logout }), [user, status, login, logout]);
  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}
