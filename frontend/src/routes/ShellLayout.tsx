import { Outlet, useNavigate } from "react-router-dom";
import { useAuth } from "@/auth/AuthContext";
import { AppShell } from "@/components/shell/AppShell";
import { TeamProvider } from "@/team/TeamContext";
import { useAnalysisNotifications } from "@/hooks/useAnalysisNotifications";

export function ShellLayout() {
  const { user, logout } = useAuth();
  const navigate = useNavigate();
  if (!user) return null; // RequireAuth guarantees a user; guards against races

  async function onLogout() {
    await logout();
    navigate("/login", { replace: true });
  }

  return (
    <TeamProvider>
      <ShellInner username={user.username} role={user.role} onLogout={onLogout} />
    </TeamProvider>
  );
}

function ShellInner({
  username,
  role,
  onLogout,
}: {
  username: string;
  role: "admin" | "analyst" | "viewer";
  onLogout: () => void;
}) {
  const { running } = useAnalysisNotifications();
  return (
    <AppShell user={{ username, role }} onLogout={onLogout} running={running}>
      <Outlet />
    </AppShell>
  );
}
