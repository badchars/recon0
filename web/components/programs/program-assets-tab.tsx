"use client";

import Link from "next/link";
import { useMemo } from "react";
import { ArrowRight } from "lucide-react";
import { Card, CardContent } from "@/components/ui/card";
import { useRuns } from "@/lib/api/hooks";
import { HostsTab } from "@/components/runs/hosts-tab";
import { formatRelative } from "@/lib/format";

// Assets tab on a Program dashboard. Shows the latest run's host list —
// reusing the existing Hosts tab (with its filters, sub-row details, and
// review-status integration). Cross-run aggregation is deferred; users
// can drill into older runs explicitly when needed.
export function ProgramAssetsTab({ programName }: { programName: string }) {
  const { data: runs, isLoading } = useRuns();

  const programRuns = useMemo(() => {
    return [...(runs ?? [])]
      .filter((r) => r.program === programName)
      .sort(
        (a, b) =>
          new Date(b.started_at).getTime() - new Date(a.started_at).getTime(),
      );
  }, [runs, programName]);

  if (isLoading) {
    return (
      <div className="text-sm text-muted-foreground p-6">Loading runs…</div>
    );
  }

  if (programRuns.length === 0) {
    return (
      <Card>
        <CardContent className="py-12 text-center text-sm text-muted-foreground">
          No runs yet for{" "}
          <span className="font-mono">{programName}</span>. Create one to
          populate assets.
        </CardContent>
      </Card>
    );
  }

  const latest = programRuns[0];

  return (
    <div className="space-y-3">
      <div className="text-xs text-muted-foreground flex items-center gap-2">
        <span>Showing assets from latest run:</span>
        <Link
          href={`/runs/${encodeURIComponent(latest.id)}`}
          className="font-mono text-foreground hover:text-sky-400 hover:underline inline-flex items-center gap-0.5"
        >
          {latest.id} <ArrowRight className="size-3" />
        </Link>
        <span>· {formatRelative(latest.started_at)}</span>
        {programRuns.length > 1 && (
          <span className="text-muted-foreground/70">
            · {programRuns.length} runs total
          </span>
        )}
      </div>
      <HostsTab runId={latest.id} />
    </div>
  );
}
