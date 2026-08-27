import { NavLink } from "react-router-dom";
import * as DropdownMenu from "@radix-ui/react-dropdown-menu";
import * as Avatar from "@radix-ui/react-avatar";
import { LogOut, ChevronDown } from "lucide-react";
import { cn } from "@/lib/cn";
import { Wordmark } from "@/components/brand/Wordmark";
import { TeamSwitcher } from "./TeamSwitcher";
import { RunningIndicator } from "./RunningIndicator";
import { Badge } from "@/components/ui/badge";
import { visibleNav, type Role } from "./nav";

export interface TopBarUser {
  username: string;
  role: Role;
}

export function TopBar({ user, onLogout, running = 0 }: { user: TopBarUser; onLogout: () => void; running?: number }) {
  const items = visibleNav(user.role);
  const initials = user.username.slice(0, 2).toUpperCase();

  return (
    <header className="sticky top-0 z-30 border-b border-border bg-bg/80 backdrop-blur">
      <div className="mx-auto flex h-14 max-w-7xl items-center gap-6 px-4">
        <NavLink to="/" aria-label="Keystone home">
          <Wordmark />
        </NavLink>

        <nav className="flex items-center gap-1" aria-label="Primary">
          {items.map(({ label, to, icon: Icon }) => (
            <NavLink
              key={to}
              to={to}
              end={to === "/"}
              className={({ isActive }) =>
                cn(
                  "flex items-center gap-2 rounded-lg px-3 py-1.5 text-sm font-medium transition-colors",
                  isActive ? "bg-panel-2 text-amber-bright" : "text-fg-muted hover:text-fg hover:bg-panel-2/60",
                )
              }
            >
              <Icon className="h-4 w-4" />
              {label}
            </NavLink>
          ))}
        </nav>

        <div className="ml-auto flex items-center gap-3">
          <RunningIndicator running={running} />
          <TeamSwitcher />
          <DropdownMenu.Root>
            <DropdownMenu.Trigger
              className="flex items-center gap-2 rounded-lg px-2 py-1.5 text-sm hover:bg-panel-2 focus-visible:ring-2 focus-visible:ring-amber"
              aria-label="Account menu"
            >
              <Avatar.Root className="flex h-7 w-7 items-center justify-center overflow-hidden rounded-full bg-stone text-xs font-semibold text-bg">
                <Avatar.Fallback>{initials}</Avatar.Fallback>
              </Avatar.Root>
              <span className="hidden text-fg sm:inline">{user.username}</span>
              <ChevronDown className="h-4 w-4 text-fg-muted" />
            </DropdownMenu.Trigger>
            <DropdownMenu.Portal>
              <DropdownMenu.Content
                align="end"
                sideOffset={8}
                className="z-50 w-56 rounded-lg border border-border bg-panel p-1 shadow-panel animate-fade-in"
              >
                <div className="flex items-center justify-between px-3 py-2">
                  <span className="text-sm text-fg">{user.username}</span>
                  <Badge variant="amber">{user.role}</Badge>
                </div>
                <DropdownMenu.Separator className="my-1 h-px bg-border" />
                <DropdownMenu.Item
                  onSelect={onLogout}
                  className="flex cursor-pointer items-center gap-2 rounded-md px-3 py-2 text-sm text-fg outline-none data-[highlighted]:bg-panel-2 data-[highlighted]:text-critical"
                >
                  <LogOut className="h-4 w-4" />
                  Sign out
                </DropdownMenu.Item>
              </DropdownMenu.Content>
            </DropdownMenu.Portal>
          </DropdownMenu.Root>
        </div>
      </div>
    </header>
  );
}
