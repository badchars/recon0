"use client";

import Link from "next/link";
import { ArrowLeft, AlertCircle, Cpu, MemoryStick, Clock } from "lucide-react";
import {
  Card,
  CardContent,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { buttonVariants } from "@/components/ui/button";
import { Progress } from "@/components/ui/progress";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { usePrograms, useRunStatus } from "@/lib/api/hooks";
import {
  STAGE_LABEL,
  STAGE_ORDER,
  isIdle,
  type RunStatus,
} from "@/lib/api/types";
import { StageNode, primaryStatFor } from "@/components/stage-node";
import { LogViewer } from "@/components/runs/log-viewer";
import { HostsTab } from "@/components/runs/hosts-tab";
import { FindingsTab } from "@/components/runs/findings-tab";
import { InvestigationsTab } from "@/components/runs/investigations-tab";
import { EndpointsTab } from "@/components/runs/endpoints-tab";
import { SmartfuzzTab } from "@/components/runs/smartfuzz-tab";
import { AttackSurfaceTab } from "@/components/runs/attack-surface-tab";
import { formatDuration, formatDurationBetween, formatRelative } from "@/lib/format";
import { cn } from "@/lib/utils";

const STATUS_VARIANT: Record<
  RunStatus,
  { label: string; className: string }
> = {
  running: { label: "running", className: "border-amber-500/50 text-amber-300" },
  done: { label: "done", className: "border-emerald-500/40 text-emerald-400" },
  failed: { label: "failed", className: "border-destructive/50 text-destructive" },
  cancelled: { label: "cancelled", className: "border-border text-muted-foreground" },
  gate_failed: { label: "gate failed", className: "border-destructive/50 text-destructive" },
  disk_full: { label: "disk full", className: "border-destructive/50 text-destructive" },
};

export function RunDetailView({ runId }: { runId: string }) {
  const { data, isLoading, isError } = useRunStatus(runId);
  const { data: programs } = usePrograms();

  if (isLoading) {
    return (
      <div className="p-6 text-sm text-muted-foreground">Loading run…</div>
    );
  }

  if (isError || !data || isIdle(data)) {
    return (
      <div className="p-6 space-y-4 max-w-3xl">
        <Link
          href="/runs"
          className={cn(
            buttonVariants({ variant: "ghost", size: "sm" }),
            "gap-1",
          )}
        >
          <ArrowLeft className="size-3.5" /> Back to runs
        </Link>
        <Card>
          <CardContent className="py-12 text-center">
            <AlertCircle className="size-8 mx-auto text-muted-foreground mb-2" />
            <p className="text-sm">Run not found.</p>
            <p className="text-xs text-muted-foreground mt-1">
              {runId} state.json couldn&apos;t be loaded.
            </p>
          </CardContent>
        </Card>
      </div>
    );
  }

  const variant = STATUS_VARIANT[data.status] ?? {
    label: data.status,
    className: "border-border text-muted-foreground",
  };
  const elapsed = formatDurationBetween(data.started_at, data.finished_at);
  const stagesDone = data.progress?.stages_done ?? 0;
  const stagesTotal = data.progress?.stages_total ?? STAGE_ORDER.length;
  const pct = stagesTotal > 0 ? (stagesDone / stagesTotal) * 100 : 0;

  return (
    <div className="p-6 space-y-6">
      <div>
        <Link
          href="/runs"
          className={cn(
            buttonVariants({ variant: "ghost", size: "sm" }),
            "gap-1 -ml-2",
          )}
        >
          <ArrowLeft className="size-3.5" /> Runs
        </Link>
      </div>

      <div className="space-y-1">
        <div className="flex items-center gap-3 flex-wrap">
          {(() => {
            const isRegistered = (programs ?? []).some(
              (p) => p.name === data.program,
            );
            return isRegistered ? (
              <Link
                href={`/programs/${encodeURIComponent(data.program)}`}
                className="text-2xl font-semibold tracking-tight hover:text-sky-400 hover:underline underline-offset-2"
              >
                {data.program}
              </Link>
            ) : (
              <div className="flex items-center gap-2">
                <h1 className="text-2xl font-semibold tracking-tight">
                  {data.program}
                </h1>
                <Link
                  href={`/programs/new?name=${encodeURIComponent(data.program)}`}
                  className="text-[11px] text-amber-300 hover:underline border border-amber-500/40 rounded px-1.5 py-0.5"
                  title="Program is not registered — click to register"
                >
                  + Register
                </Link>
              </div>
            );
          })()}
          <Badge variant="outline" className={variant.className}>
            {variant.label}
          </Badge>
        </div>
        <div className="text-sm text-muted-foreground font-mono">
          {data.domains?.length && data.domains.length > 1
            ? data.domains.join(", ")
            : data.domain}
        </div>
        <div className="text-xs text-muted-foreground">
          {data.job_id} · started {formatRelative(data.started_at)} ·{" "}
          <Clock className="inline size-3 -mt-0.5" /> {elapsed}
        </div>
      </div>

      <Card>
        <CardHeader>
          <CardTitle className="text-sm flex items-center justify-between">
            <span>Pipeline</span>
            <span className="text-xs font-normal text-muted-foreground">
              {stagesDone}/{stagesTotal} · {Math.round(pct)}%
            </span>
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <Progress value={pct} />
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
        </CardContent>
      </Card>

      <Tabs defaultValue="overview">
        <TabsList>
          <TabsTrigger value="overview">Overview</TabsTrigger>
          <TabsTrigger value="hosts">Hosts</TabsTrigger>
          <TabsTrigger value="findings">Findings</TabsTrigger>
          <TabsTrigger value="investigations">Investigations</TabsTrigger>
          <TabsTrigger value="endpoints">Endpoints</TabsTrigger>
          <TabsTrigger value="smartfuzz">Smartfuzz</TabsTrigger>
          <TabsTrigger value="attack-surface">Attack Surface</TabsTrigger>
          <TabsTrigger value="logs">Logs</TabsTrigger>
        </TabsList>

        <TabsContent value="overview" className="space-y-4 pt-4">
          <Card>
            <CardHeader>
              <CardTitle className="text-sm">Stage breakdown</CardTitle>
            </CardHeader>
            <CardContent className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead className="text-xs text-muted-foreground">
                  <tr className="border-b">
                    <th className="text-left font-medium py-2 pr-4">Stage</th>
                    <th className="text-left font-medium py-2 pr-4">Status</th>
                    <th className="text-right font-medium py-2 pr-4">Duration</th>
                    <th className="text-left font-medium py-2 pr-4">Stats</th>
                    <th className="text-left font-medium py-2">Providers</th>
                  </tr>
                </thead>
                <tbody>
                  {STAGE_ORDER.map((s) => {
                    const st = data.stages?.[s];
                    const stats = st?.stats ?? {};
                    const provs = st?.providers ?? {};
                    return (
                      <tr key={s} className="border-b last:border-0">
                        <td className="py-2 pr-4 font-medium">
                          {STAGE_LABEL[s]}
                        </td>
                        <td className="py-2 pr-4 text-muted-foreground">
                          {st?.status ?? "pending"}
                        </td>
                        <td className="py-2 pr-4 text-right tabular-nums text-xs">
                          {formatDuration(st?.duration_s)}
                        </td>
                        <td className="py-2 pr-4 text-xs text-muted-foreground">
                          {Object.entries(stats)
                            .map(([k, v]) => `${k}=${v}`)
                            .join(", ") || "—"}
                        </td>
                        <td className="py-2 text-xs text-muted-foreground">
                          {Object.entries(provs)
                            .map(
                              ([n, p]) =>
                                `${n}:${p.status}${p.count ? `(${p.count})` : ""}`,
                            )
                            .join("  ") || "—"}
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </CardContent>
          </Card>

          {data.errors && data.errors.length > 0 && (
            <Card>
              <CardHeader>
                <CardTitle className="text-sm flex items-center gap-2 text-destructive">
                  <AlertCircle className="size-4" /> Errors ({data.errors.length})
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-2">
                {data.errors.map((e, i) => (
                  <div
                    key={i}
                    className="text-xs font-mono bg-destructive/10 border border-destructive/20 rounded px-3 py-2"
                  >
                    <span className="text-muted-foreground">{e.time}</span>{" "}
                    <span className="text-foreground">[{e.stage}/{e.provider}]</span>{" "}
                    <span className="text-destructive">{e.error}</span>
                    {e.fatal && (
                      <span className="ml-2 text-destructive font-bold">
                        FATAL
                      </span>
                    )}
                  </div>
                ))}
              </CardContent>
            </Card>
          )}

          {data.resources && (
            <Card>
              <CardHeader>
                <CardTitle className="text-sm">Resources</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="grid grid-cols-2 md:grid-cols-5 gap-4 text-sm">
                  <div className="flex items-center gap-2">
                    <Cpu className="size-4 text-muted-foreground" />
                    <div>
                      <div className="font-medium">{data.resources.cores}</div>
                      <div className="text-xs text-muted-foreground">cores</div>
                    </div>
                  </div>
                  <div className="flex items-center gap-2">
                    <MemoryStick className="size-4 text-muted-foreground" />
                    <div>
                      <div className="font-medium">{data.resources.ram_gb} GB</div>
                      <div className="text-xs text-muted-foreground">RAM</div>
                    </div>
                  </div>
                  <div>
                    <div className="font-medium">{data.resources.threads_full}</div>
                    <div className="text-xs text-muted-foreground">threads (full)</div>
                  </div>
                  <div>
                    <div className="font-medium">{data.resources.threads_heavy}</div>
                    <div className="text-xs text-muted-foreground">threads (heavy)</div>
                  </div>
                  <div>
                    <div className="font-medium">{data.resources.threads_light}</div>
                    <div className="text-xs text-muted-foreground">threads (light)</div>
                  </div>
                </div>
              </CardContent>
            </Card>
          )}
        </TabsContent>

        <TabsContent value="hosts" className="pt-4">
          <HostsTab runId={runId} />
        </TabsContent>

        <TabsContent value="findings" className="pt-4">
          <FindingsTab runId={runId} />
        </TabsContent>

        <TabsContent value="investigations" className="pt-4">
          <InvestigationsTab runId={runId} />
        </TabsContent>

        <TabsContent value="endpoints" className="pt-4">
          <EndpointsTab runId={runId} />
        </TabsContent>

        <TabsContent value="smartfuzz" className="pt-4">
          <SmartfuzzTab runId={runId} />
        </TabsContent>

        <TabsContent value="attack-surface" className="pt-4">
          <AttackSurfaceTab runId={runId} />
        </TabsContent>

        <TabsContent value="logs" className="pt-4">
          <LogViewer runId={runId} />
        </TabsContent>
      </Tabs>
    </div>
  );
}
