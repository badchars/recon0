"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import {
  Activity,
  Briefcase,
  Bug,
  ListChecks,
  Settings as SettingsIcon,
  Radar,
} from "lucide-react";
import { cn } from "@/lib/utils";

const NAV = [
  { href: "/", label: "Dashboard", icon: Activity },
  { href: "/runs", label: "Runs", icon: ListChecks },
  { href: "/programs", label: "Programs", icon: Briefcase },
  { href: "/vulnerabilities", label: "Vulnerabilities", icon: Bug },
  { href: "/settings", label: "Settings", icon: SettingsIcon },
] as const;

export function Sidebar() {
  const pathname = usePathname();

  return (
    <aside className="w-56 shrink-0 border-r bg-sidebar text-sidebar-foreground flex flex-col">
      <div className="h-14 px-4 border-b flex items-center gap-2">
        <Radar className="size-5 text-primary" />
        <span className="font-semibold tracking-tight">recon0</span>
        <span className="ml-auto text-xs text-muted-foreground">panel</span>
      </div>
      <nav className="flex-1 p-2 space-y-1">
        {NAV.map((item) => {
          const active =
            item.href === "/"
              ? pathname === "/"
              : pathname?.startsWith(item.href);
          const Icon = item.icon;
          return (
            <Link
              key={item.href}
              href={item.href}
              className={cn(
                "flex items-center gap-2 rounded-md px-3 py-2 text-sm transition-colors",
                active
                  ? "bg-sidebar-accent text-sidebar-accent-foreground"
                  : "text-muted-foreground hover:bg-sidebar-accent hover:text-sidebar-accent-foreground",
              )}
            >
              <Icon className="size-4" />
              {item.label}
            </Link>
          );
        })}
      </nav>
      <div className="p-3 border-t text-[11px] text-muted-foreground">
        recon0 panel · v0.1.0
      </div>
    </aside>
  );
}
