import type { LucideIcon } from "lucide-react";
import { LayoutDashboard, Boxes, FileCode2, Users, Shield, Settings, ScrollText } from "lucide-react";

export type Role = "admin" | "analyst" | "viewer";

export interface NavItem {
  label: string;
  to: string;
  icon: LucideIcon;
  /** Minimum roles allowed to see the item; omit = everyone authenticated. */
  roles?: Role[];
}

export const NAV_ITEMS: NavItem[] = [
  { label: "Dashboard", to: "/", icon: LayoutDashboard },
  { label: "Binaries", to: "/binaries", icon: Boxes },
  // No `roles`: every authenticated user reads the library; write controls are
  // gated inside the page (and server-side) rather than by hiding the nav item.
  { label: "Rule sets", to: "/rule-sets", icon: FileCode2 },
  { label: "Users", to: "/admin/users", icon: Users, roles: ["admin"] },
  { label: "Teams", to: "/admin/teams", icon: Shield, roles: ["admin"] },
  { label: "Settings", to: "/admin/settings", icon: Settings, roles: ["admin"] },
  { label: "Audit", to: "/admin/audit", icon: ScrollText, roles: ["admin"] },
];

export function visibleNav(role: Role | undefined): NavItem[] {
  return NAV_ITEMS.filter((i) => !i.roles || (role && i.roles.includes(role)));
}
