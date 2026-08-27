import { Outlet, useNavigate } from "react-router-dom";
import { useAuth } from "@/auth/AuthContext";
import { AppShell } from "@/components/shell/AppShell";

export function ShellLayout() {
  const { user, logout } = useAuth();
  const navigate = useNavigate();
  if (!user) return null; // RequireAuth guarantees a user; guards against races

  async function onLogout() {
    await logout();
    navigate("/login", { replace: true });
  }

  return (
    <AppShell user={{ username: user.username, role: user.role }} onLogout={onLogout}>
      <Outlet />
    </AppShell>
  );
}
