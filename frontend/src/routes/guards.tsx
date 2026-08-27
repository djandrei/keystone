import { Navigate, Outlet } from "react-router-dom";
import { useAuth } from "@/auth/AuthContext";
import type { Role } from "@/lib/api";
import { Logo } from "@/components/brand/Logo";

function Splash() {
  return (
    <div className="flex min-h-screen items-center justify-center bg-bg">
      <Logo className="h-12 w-12 animate-pulse" />
    </div>
  );
}

export function RequireAuth() {
  const { user, status } = useAuth();
  if (status === "loading") return <Splash />;
  return user ? <Outlet /> : <Navigate to="/login" replace />;
}

export function RequireRole({ roles }: { roles: Role[] }) {
  const { user } = useAuth();
  return user && roles.includes(user.role) ? <Outlet /> : <Navigate to="/" replace />;
}
