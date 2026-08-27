import { TopBar, type TopBarUser } from "./TopBar";

export function AppShell({
  user,
  onLogout,
  children,
}: {
  user: TopBarUser;
  onLogout: () => void;
  children: React.ReactNode;
}) {
  return (
    <div className="flex min-h-full flex-col bg-bg">
      <TopBar user={user} onLogout={onLogout} />
      <main className="mx-auto w-full max-w-7xl flex-1 px-4 py-8">{children}</main>
    </div>
  );
}
