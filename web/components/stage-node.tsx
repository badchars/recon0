"use client";

import { CheckCircle2, Circle, Loader2, XCircle, MinusCircle } from "lucide-react";
import { cn } from "@/lib/utils";
import { STAGE_LABEL, type StageState } from "@/lib/api/types";

export function StageNode({
  name,
  state,
  primaryStat,
}: {
  name: string;
  state: StageState | undefined;
  primaryStat?: number;
}) {
  const status = state?.status ?? "pending";

  let icon = <Circle className="size-4 text-muted-foreground" />;
  let tone = "text-muted-foreground border-border";

  if (status === "running") {
    icon = <Loader2 className="size-4 animate-spin text-amber-400" />;
    tone = "text-amber-300 border-amber-500/40 bg-amber-500/5";
  } else if (status === "done") {
    icon = <CheckCircle2 className="size-4 text-emerald-500" />;
    tone = "text-foreground border-emerald-500/30";
  } else if (status === "error") {
    icon = <XCircle className="size-4 text-destructive" />;
    tone = "text-destructive border-destructive/40 bg-destructive/5";
  } else if (status === "skipped") {
    icon = <MinusCircle className="size-4 text-muted-foreground/60" />;
    tone = "text-muted-foreground/60 border-border";
  }

  return (
    <div
      className={cn(
        "rounded-md border px-3 py-2 min-w-[120px] flex flex-col gap-0.5",
        tone,
      )}
    >
      <div className="flex items-center gap-1.5 text-xs font-medium">
        {icon}
        <span>{STAGE_LABEL[name] ?? name}</span>
      </div>
      <div className="text-[11px] tabular-nums text-muted-foreground">
        {status === "done" || status === "running"
          ? primaryStat !== undefined
            ? primaryStat.toLocaleString()
            : status === "running"
              ? "running…"
              : "—"
          : status === "skipped"
            ? "skipped"
            : status === "error"
              ? "error"
              : "—"}
      </div>
    </div>
  );
}

// Pick the most representative stat per stage to display in the node.
export function primaryStatFor(
  stage: string,
  stats: Record<string, number> | undefined,
): number | undefined {
  if (!stats) return undefined;
  const map: Record<string, string[]> = {
    enum: ["subdomains"],
    resolve: ["alive"],
    permute: ["total_alive", "added"],
    probe: ["unique_hosts", "live_hosts"],
    crawl: ["total_urls"],
    portscan: ["open_ports"],
    discover: ["endpoints"],
    analyze: ["findings"],
    vuln: ["findings"],
    collect: ["intel_generated"],
  };
  const keys = map[stage] ?? [];
  for (const k of keys) {
    if (typeof stats[k] === "number") return stats[k];
  }
  return undefined;
}
