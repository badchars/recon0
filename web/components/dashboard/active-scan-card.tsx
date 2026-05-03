"use client";

import Link from "next/link";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Progress } from "@/components/ui/progress";
import { buttonVariants } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { ArrowRight, Clock } from "lucide-react";
import { useStatus } from "@/lib/api/hooks";
import { isIdle, STAGE_ORDER } from "@/lib/api/types";
import { StageNode, primaryStatFor } from "@/components/stage-node";
import { formatDurationBetween } from "@/lib/format";

export function ActiveScanCard() {
  const { data, isLoading } = useStatus();

  if (isLoading) {
    return (
      <Card className="bg-muted/20">
        <CardContent className="py-10 text-center text-sm text-muted-foreground">
          Loading status…
        </CardContent>
      </Card>
    );
  }

  if (!data || isIdle(data)) {
    return (
      <Card className="bg-muted/20 border-dashed">
        <CardContent className="py-12 text-center">
          <p className="text-sm text-muted-foreground">No active scan</p>
          <p className="text-xs text-muted-foreground/70 mt-1">
            Use{" "}
            <kbd className="rounded border bg-background px-1.5 py-0.5 text-[10px] font-mono">
              Create Run
            </kbd>{" "}
            to queue one.
          </p>
        </CardContent>
      </Card>
    );
  }

  const elapsed = formatDurationBetween(data.started_at, data.finished_at);
  const stagesDone = data.progress?.stages_done ?? 0;
  const stagesTotal = data.progress?.stages_total ?? STAGE_ORDER.length;
  const pct = stagesTotal > 0 ? (stagesDone / stagesTotal) * 100 : 0;

  return (
    <Card>
      <CardHeader className="flex flex-row items-center gap-3 space-y-0">
        <Badge variant="outline" className="border-amber-500/50 text-amber-300">
          <span className="size-1.5 rounded-full bg-amber-400 animate-pulse mr-1.5" />
          {data.status}
        </Badge>
        <CardTitle className="flex flex-col">
          <span>{data.program}</span>
          <span className="text-xs font-normal text-muted-foreground">
            {data.domains?.length && data.domains.length > 1
              ? `${data.domain} +${data.domains.length - 1} more`
              : data.domain}
          </span>
        </CardTitle>
        <div className="ml-auto flex items-center gap-1 text-xs text-muted-foreground">
          <Clock className="size-3.5" />
          <span>{elapsed}</span>
        </div>
        <Link
          href={`/runs/${data.job_id}`}
          className={buttonVariants({ size: "sm", variant: "ghost" })}
        >
          Details <ArrowRight className="size-3.5" />
        </Link>
      </CardHeader>

      <CardContent className="space-y-4">
        <div className="space-y-2">
          <div className="flex items-center justify-between text-xs">
            <span className="text-muted-foreground">
              Stage {Math.min(stagesDone + 1, stagesTotal)}/{stagesTotal}
              {data.current_stage ? ` · ${data.current_stage}` : ""}
              {data.progress?.current_provider
                ? ` · ${data.progress.current_provider}`
                : ""}
            </span>
            <span className="tabular-nums text-muted-foreground">
              {Math.round(pct)}%
            </span>
          </div>
          <Progress value={pct} />
        </div>

        <div className="overflow-x-auto">
          <div className="flex gap-2 pb-1">
            {STAGE_ORDER.map((s) => (
              <StageNode
                key={s}
                name={s}
                state={data.stages?.[s]}
                primaryStat={primaryStatFor(s, data.stages?.[s]?.stats)}
              />
            ))}
          </div>
        </div>

        {data.errors && data.errors.length > 0 && (
          <div className="text-xs text-destructive/90 bg-destructive/10 border border-destructive/20 rounded-md p-2">
            {data.errors.length} error{data.errors.length > 1 ? "s" : ""} —{" "}
            <span className="font-mono">{data.errors[0].provider}</span>:{" "}
            {data.errors[0].error}
          </div>
        )}
      </CardContent>
    </Card>
  );
}
