"use client";

import Link from "next/link";
import { useMemo, useState } from "react";
import { toast } from "sonner";
import { X } from "lucide-react";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { useQueue, useRemoveQueued, useRuns } from "@/lib/api/hooks";
import { formatDurationBetween, formatRelative } from "@/lib/format";
import type { RunStatus } from "@/lib/api/types";

// "Merged row" type — covers both real Runs (have job_id, state.json) and
// synthesized queue rows for jobs that haven't been picked up yet
// (status=queued, no run_id, no state).
interface MergedRow {
  key: string;
  id: string; // run id (real) or queue id (q-XXX) for waiting rows
  program: string;
  domain: string;
  status: RunStatus | "waiting";
  started_at: string;
  finished_at?: string;
  isWaiting: boolean;
  queueID?: string; // populated for waiting rows so we can cancel them
}

const STATUS_VARIANT: Record<
  RunStatus | "waiting",
  { label: string; className: string }
> = {
  waiting: {
    label: "waiting",
    className: "border-sky-500/40 text-sky-400 bg-sky-500/5",
  },
  running: { label: "running", className: "border-amber-500/50 text-amber-300" },
  done: { label: "done", className: "border-emerald-500/40 text-emerald-400" },
  failed: { label: "failed", className: "border-destructive/50 text-destructive" },
  cancelled: { label: "cancelled", className: "border-border text-muted-foreground" },
  gate_failed: { label: "gate failed", className: "border-destructive/50 text-destructive" },
  disk_full: { label: "disk full", className: "border-destructive/50 text-destructive" },
};

const STATUS_FILTERS = ["all", "waiting", "running", "done", "failed", "cancelled", "gate_failed"] as const;
type StatusFilter = (typeof STATUS_FILTERS)[number];

// When `programFilter` is provided, the table is scoped to a single
// program (used by the Program dashboard). The program filter dropdown
// is then hidden since it would be redundant.
export function RunsTable({ programFilter }: { programFilter?: string } = {}) {
  const { data, isLoading } = useRuns();
  const { data: queue } = useQueue();
  const removeQueued = useRemoveQueued();
  const [search, setSearch] = useState("");
  const [statusFilter, setStatusFilter] = useState<StatusFilter>("all");
  const [programDropdown, setProgramDropdown] = useState<string>("all");

  const scoped = programFilter !== undefined;
  const effectiveProgram = scoped ? programFilter! : programDropdown;

  // Merge real runs + queue waiting jobs into a unified row list. Waiting
  // jobs (queue.status="queued") have no state.json yet so they're absent
  // from /api/runs; we synthesize a row with status="waiting" for them.
  const allRows: MergedRow[] = useMemo(() => {
    const real: MergedRow[] = (data ?? []).map((r) => ({
      key: `r-${r.id}`,
      id: r.id,
      program: r.program,
      domain: r.domain,
      status: r.status,
      started_at: r.started_at,
      finished_at: r.finished_at,
      isWaiting: false,
    }));
    const waiting: MergedRow[] = (queue?.jobs ?? [])
      .filter((j) => j.status === "queued")
      .map((j) => ({
        key: `q-${j.id}`,
        id: j.id,
        program: j.program,
        domain: j.domain,
        status: "waiting",
        started_at: j.created_at,
        isWaiting: true,
        queueID: j.id,
      }));
    return [...waiting, ...real];
  }, [data, queue]);

  const programs = useMemo(() => {
    if (scoped) return [];
    const set = new Set<string>();
    allRows.forEach((r) => r.program && set.add(r.program));
    return ["all", ...Array.from(set).sort()];
  }, [allRows, scoped]);

  const filtered = useMemo(() => {
    let rows = [...allRows];
    if (search) {
      const q = search.toLowerCase();
      rows = rows.filter(
        (r) =>
          r.domain.toLowerCase().includes(q) ||
          r.program.toLowerCase().includes(q) ||
          r.id.toLowerCase().includes(q),
      );
    }
    if (statusFilter !== "all") {
      rows = rows.filter((r) => r.status === statusFilter);
    }
    if (effectiveProgram !== "all") {
      rows = rows.filter((r) => r.program === effectiveProgram);
    }
    rows.sort((a, b) => {
      // Waiting rows always sort to top (they're the user's "next up")
      if (a.isWaiting !== b.isWaiting) return a.isWaiting ? -1 : 1;
      return new Date(b.started_at).getTime() - new Date(a.started_at).getTime();
    });
    return rows;
  }, [allRows, search, statusFilter, effectiveProgram]);

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center gap-2">
        <Input
          placeholder="Search domain, program, or run ID…"
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          className="max-w-xs"
        />
        <Select value={statusFilter} onValueChange={(v) => setStatusFilter(v as StatusFilter)}>
          <SelectTrigger className="w-[160px]">
            <SelectValue placeholder="Status" />
          </SelectTrigger>
          <SelectContent>
            {STATUS_FILTERS.map((s) => (
              <SelectItem key={s} value={s}>
                {s === "all" ? "All statuses" : s}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
        {!scoped && (
          <Select value={programDropdown} onValueChange={(v) => setProgramDropdown(v ?? "all")}>
            <SelectTrigger className="w-[180px]">
              <SelectValue placeholder="Program" />
            </SelectTrigger>
            <SelectContent>
              {programs.map((p) => (
                <SelectItem key={p} value={p}>
                  {p === "all" ? "All programs" : p}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        )}
        <div className="ml-auto text-xs text-muted-foreground">
          {(() => {
            const waiting = filtered.filter((r) => r.isWaiting).length;
            const runs = filtered.length - waiting;
            const parts: string[] = [];
            if (runs > 0) parts.push(`${runs} run${runs === 1 ? "" : "s"}`);
            if (waiting > 0) parts.push(`${waiting} waiting`);
            return parts.length > 0 ? parts.join(" · ") : "0 entries";
          })()}
        </div>
      </div>

      <div className="rounded-md border">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead className="w-[120px]">Status</TableHead>
              <TableHead>Program</TableHead>
              <TableHead>Domain</TableHead>
              <TableHead className="hidden md:table-cell">Run ID</TableHead>
              <TableHead className="text-right">Duration</TableHead>
              <TableHead className="text-right">Started</TableHead>
              <TableHead className="w-[40px]" />
            </TableRow>
          </TableHeader>
          <TableBody>
            {isLoading ? (
              <TableRow>
                <TableCell colSpan={7} className="text-center py-8 text-muted-foreground">
                  Loading…
                </TableCell>
              </TableRow>
            ) : filtered.length === 0 ? (
              <TableRow>
                <TableCell colSpan={7} className="text-center py-8 text-muted-foreground">
                  No runs match the current filters.
                </TableCell>
              </TableRow>
            ) : (
              filtered.map((r) => {
                const v = STATUS_VARIANT[r.status] ?? {
                  label: r.status,
                  className: "border-border text-muted-foreground",
                };
                // Waiting rows have no state.json — skip the link, render
                // plain cells with a small remove (X) action.
                if (r.isWaiting) {
                  return (
                    <TableRow key={r.key} className="bg-sky-500/5 hover:bg-sky-500/10">
                      <TableCell>
                        <Badge variant="outline" className={v.className}>
                          {v.label}
                        </Badge>
                      </TableCell>
                      <TableCell className="font-medium">{r.program}</TableCell>
                      <TableCell className="font-mono text-xs">{r.domain}</TableCell>
                      <TableCell className="hidden md:table-cell">
                        <span className="font-mono text-xs text-muted-foreground">
                          {r.id} <span className="opacity-60">(in queue)</span>
                        </span>
                      </TableCell>
                      <TableCell className="text-right text-xs text-muted-foreground">
                        —
                      </TableCell>
                      <TableCell className="text-right tabular-nums text-xs text-muted-foreground">
                        queued {formatRelative(r.started_at)}
                      </TableCell>
                      <TableCell>
                        <Button
                          variant="ghost"
                          size="icon"
                          className="size-7"
                          onClick={async () => {
                            try {
                              await removeQueued.mutateAsync(r.queueID!);
                              toast.success(`Removed ${r.queueID} from queue`);
                            } catch {
                              toast.error("Could not remove job");
                            }
                          }}
                          aria-label="Remove from queue"
                        >
                          <X className="size-3.5" />
                        </Button>
                      </TableCell>
                    </TableRow>
                  );
                }
                return (
                  <TableRow
                    key={r.key}
                    className="cursor-pointer hover:bg-muted/50"
                  >
                    <TableCell>
                      <Link href={`/runs/${r.id}`} className="block">
                        <Badge variant="outline" className={v.className}>
                          {v.label}
                        </Badge>
                      </Link>
                    </TableCell>
                    <TableCell>
                      <Link href={`/runs/${r.id}`} className="block font-medium">
                        {r.program}
                      </Link>
                    </TableCell>
                    <TableCell>
                      <Link href={`/runs/${r.id}`} className="block font-mono text-xs">
                        {r.domain}
                      </Link>
                    </TableCell>
                    <TableCell className="hidden md:table-cell">
                      <Link href={`/runs/${r.id}`} className="block font-mono text-xs text-muted-foreground">
                        {r.id}
                      </Link>
                    </TableCell>
                    <TableCell className="text-right tabular-nums text-xs text-muted-foreground">
                      {formatDurationBetween(r.started_at, r.finished_at ?? null)}
                    </TableCell>
                    <TableCell className="text-right tabular-nums text-xs text-muted-foreground">
                      {formatRelative(r.started_at)}
                    </TableCell>
                    <TableCell />
                  </TableRow>
                );
              })
            )}
          </TableBody>
        </Table>
      </div>
    </div>
  );
}
