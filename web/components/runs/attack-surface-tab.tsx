"use client";

import { useMemo, useState } from "react";
import { ExternalLink, FileWarning, Lock, Plug } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { useRunAttackSurface } from "@/lib/api/hooks";
import { hostnameFromURL, normalizeHostname } from "@/lib/host";

// recon0's collector emits a mix of absolute URLs and bare paths into
// attack-surface.json (paths come from JS extraction where the host
// context was lost). We only treat http(s) absolute URLs as clickable
// to avoid the browser resolving "/admin/home" to the panel itself.
function isAbsoluteHttp(s: string): boolean {
  return /^https?:\/\//i.test(s);
}

export function AttackSurfaceTab({
  runId,
  hostFilter,
}: {
  runId: string;
  hostFilter?: string;
}) {
  const { data, isLoading, isError } = useRunAttackSurface(runId);
  const [search, setSearch] = useState("");

  const surface = useMemo(() => {
    if (!data) return { api: [] as string[], admin: [] as string[], files: [] as string[] };
    const apply = (urls: string[]) => {
      let list = urls;
      if (hostFilter) {
        // Path-only entries don't carry a host — they get filtered out
        // when a host filter is active (we can't claim they belong to
        // any specific host).
        const canon = normalizeHostname(hostFilter);
        list = list.filter((u) => isAbsoluteHttp(u) && hostnameFromURL(u) === canon);
      }
      const q = search.trim().toLowerCase();
      if (q) list = list.filter((u) => u.toLowerCase().includes(q));
      return list;
    };
    return {
      api: apply(data.api_endpoints ?? []),
      admin: apply(data.admin_panels ?? []),
      files: apply(data.exposed_files ?? []),
    };
  }, [data, hostFilter, search]);

  if (isError) {
    return (
      <div className="text-sm text-destructive p-6">
        Failed to load attack surface.
      </div>
    );
  }

  if (isLoading) {
    return (
      <div className="text-sm text-muted-foreground p-6">Loading attack surface…</div>
    );
  }

  if (!data) {
    return (
      <div className="text-sm text-muted-foreground p-6">
        No attack surface data — collect stage may not have run.
      </div>
    );
  }

  return (
    <div className="space-y-4">
      <div className="flex items-center gap-2">
        <Input
          placeholder="Search across all categories…"
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          className="max-w-sm font-mono text-xs"
        />
      </div>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <SurfaceCard
          icon={<Plug className="size-4" />}
          title="API endpoints"
          urls={surface.api}
          tone="text-sky-400 border-sky-500/30"
        />
        <SurfaceCard
          icon={<Lock className="size-4" />}
          title="Admin panels"
          urls={surface.admin}
          tone="text-amber-300 border-amber-500/30"
        />
        <SurfaceCard
          icon={<FileWarning className="size-4" />}
          title="Exposed files"
          urls={surface.files}
          tone="text-destructive border-destructive/30"
        />
      </div>
    </div>
  );
}

function SurfaceCard({
  icon,
  title,
  urls,
  tone,
}: {
  icon: React.ReactNode;
  title: string;
  urls: string[];
  tone: string;
}) {
  return (
    <Card className="min-w-0">
      <CardHeader>
        <CardTitle className="text-sm flex items-center gap-2">
          <span className={tone}>{icon}</span>
          <span>{title}</span>
          <span className="ml-auto text-xs font-normal text-muted-foreground tabular-nums">
            {urls.length}
          </span>
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-1 text-xs">
        {urls.length === 0 ? (
          <div className="text-muted-foreground italic">none</div>
        ) : (
          urls.map((u, i) => {
            const clickable = isAbsoluteHttp(u);
            if (clickable) {
              return (
                <a
                  key={`${u}-${i}`}
                  href={u}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="flex items-center gap-1 font-mono text-[11px] hover:underline hover:text-sky-400 break-all"
                >
                  <ExternalLink className="size-3 shrink-0 text-muted-foreground" />
                  <span className="min-w-0 break-all">{u}</span>
                </a>
              );
            }
            return (
              <div
                key={`${u}-${i}`}
                className="flex items-center gap-1 font-mono text-[11px] text-muted-foreground"
                title="Path only — no host context from collector"
              >
                <span className="shrink-0 rounded border border-border px-1 text-[9px] uppercase tracking-wider">
                  path
                </span>
                <span className="min-w-0 break-all">{u}</span>
              </div>
            );
          })
        )}
      </CardContent>
    </Card>
  );
}
