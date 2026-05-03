"use client";

import Link from "next/link";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { ArrowRight } from "lucide-react";
import { useRuns } from "@/lib/api/hooks";
import { formatRelative, formatDurationBetween } from "@/lib/format";
import type { RunStatus } from "@/lib/api/types";

const STATUS_VARIANT: Record<
  RunStatus,
  { label: string; className: string }
> = {
  running: {
    label: "running",
    className: "border-amber-500/50 text-amber-300",
  },
  done: {
    label: "done",
    className: "border-emerald-500/40 text-emerald-400",
  },
  failed: {
    label: "failed",
    className: "border-destructive/50 text-destructive",
  },
  cancelled: {
    label: "cancelled",
    className: "border-border text-muted-foreground",
  },
  gate_failed: {
    label: "gate failed",
    className: "border-destructive/50 text-destructive",
  },
  disk_full: {
    label: "disk full",
    className: "border-destructive/50 text-destructive",
  },
};

export function RecentRuns() {
  const { data, isLoading } = useRuns();

  const sorted = [...(data ?? [])]
    .sort(
      (a, b) =>
        new Date(b.started_at).getTime() - new Date(a.started_at).getTime(),
    )
    .slice(0, 5);

  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-sm flex items-center justify-between">
          <span>Recent runs</span>
          <Link
            href="/runs"
            className="text-xs font-normal text-muted-foreground hover:text-foreground inline-flex items-center gap-0.5"
          >
            View all <ArrowRight className="size-3" />
          </Link>
        </CardTitle>
      </CardHeader>
      <CardContent>
        {isLoading ? (
          <div className="text-xs text-muted-foreground">Loading…</div>
        ) : sorted.length === 0 ? (
          <div className="text-xs text-muted-foreground">No runs yet.</div>
        ) : (
          <ul className="divide-y">
            {sorted.map((run) => {
              const variant = STATUS_VARIANT[run.status] ?? {
                label: run.status,
                className: "border-border text-muted-foreground",
              };
              const duration = formatDurationBetween(
                run.started_at,
                run.finished_at ?? null,
              );
              return (
                <li key={run.id}>
                  <Link
                    href={`/runs/${run.id}`}
                    className="flex items-center gap-3 py-2.5 hover:bg-muted/50 -mx-2 px-2 rounded-md transition-colors"
                  >
                    <Badge variant="outline" className={variant.className}>
                      {variant.label}
                    </Badge>
                    <div className="flex-1 min-w-0">
                      <div className="truncate text-sm font-medium">
                        {run.program}
                      </div>
                      <div className="truncate text-xs text-muted-foreground font-mono">
                        {run.domain}
                      </div>
                    </div>
                    <div className="text-right text-xs text-muted-foreground tabular-nums">
                      <div>{duration}</div>
                      <div>{formatRelative(run.started_at)}</div>
                    </div>
                  </Link>
                </li>
              );
            })}
          </ul>
        )}
      </CardContent>
    </Card>
  );
}
