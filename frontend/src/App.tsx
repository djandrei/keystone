import { Navigate, Route, Routes } from "react-router-dom";
import { LoginPage } from "@/pages/LoginPage";
import { DashboardPage } from "@/pages/DashboardPage";
import { PlaceholderPage } from "@/pages/PlaceholderPage";
import { UsersAdminPage } from "@/pages/admin/UsersAdminPage";
import { TeamsAdminPage } from "@/pages/admin/TeamsAdminPage";
import { SettingsPage } from "@/pages/admin/SettingsPage";
import { RequireAuth, RequireRole } from "@/routes/guards";
import { ShellLayout } from "@/routes/ShellLayout";

export function App() {
  return (
    <Routes>
      <Route path="/login" element={<LoginPage />} />
      <Route element={<RequireAuth />}>
        <Route element={<ShellLayout />}>
          <Route path="/" element={<DashboardPage />} />
          <Route
            path="/analyses"
            element={<PlaceholderPage title="Analyses" note="Analyses land in M2." />}
          />
          <Route element={<RequireRole roles={["admin"]} />}>
            <Route path="/admin/users" element={<UsersAdminPage />} />
            <Route path="/admin/teams" element={<TeamsAdminPage />} />
            <Route path="/admin/settings" element={<SettingsPage />} />
          </Route>
        </Route>
      </Route>
      <Route path="*" element={<Navigate to="/" replace />} />
    </Routes>
  );
}
