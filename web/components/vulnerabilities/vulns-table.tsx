"use client";

import Link from "next/link";
import { useMemo, useState } from "react";
import { Bug, Plus } from "lucide-react";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { buttonVariants } from "@/components/ui/button";
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
import { useVulnerabilities, usePrograms } from "@/lib/api/hooks";
import { SeverityBadge } from "@/components/severity-badge";
import { formatRelative } from "@/lib/format";
import { cn } from "@/lib/utils";
import type { Program, Severity, SubmissionStatus } from "@/lib/api/types";
import { SUBMISSION_STATUSES } from "@/lib/api/types";

const SEVERITY_RANK: Record<Severity, number> = {
  critical: 5,
  high: 4,
  medium: 3,
  low: 2,
  info: 1,
};

const VENDOR_VARIANT: Record<string, string> = {
  hackerone: "border-border text-muted-foreground",
  bugcrowd: "border-amber-500/40 text-amber-300",
  yeswehack: "border-emerald-500/40 text-emerald-400",
  intigriti: "border-sky-500/40 text-sky-400",
  private: "border-border text-muted-foreground",
};

const STATUS_VARIANT: Record<
  SubmissionStatus,
  { label: string; className: string }
> = {
  wait: { label: "wait", className: "border-border text-muted-foreground" },
  submitted: { label: "submitted", className: "border-sky-500/40 text-sky-400" },
  triaged: { label: "triaged", className: "border-amber-500/40 text-amber-300" },
  na: { label: "n/a", className: "border-border text-muted-foreground/70" },
  duplicate: { label: "duplicate", className: "border-border text-muted-foreground/70" },
};

// When `programFilter` is set, the table scopes to a single program and
// hides the program filter dropdown (used by Program dashboard).
export function VulnsTable({
  programFilter,
}: {
  programFilter?: string;
} = {}) {
  const { data: vulns, isLoading, isError } = useVulnerabilities();
  const { data: programs } = usePrograms();
  const [search, setSearch] = useState("");
  const [severity, setSeverity] = useState<"all" | Severity>("all");
  const [status, setStatus] = useState<"all" | SubmissionStatus>("all");
  const [programDropdown, setProgramDropdown] = useState<string>("all");
  const [tag, setTag] = useState<string>("all");

  const scoped = programFilter !== undefined;
  const effectiveProgram = scoped ? programFilter! : programDropdown;

  const list = vulns ?? [];

  const programOptions = useMemo(() => {
    const set = new Set<string>();
    list.forEach((v) => v.program && set.add(v.program));
    (programs ?? []).forEach((p) => set.add(p.name));
    return Array.from(set).sort();
  }, [list, programs]);

  const programByName = useMemo(() => {
    const m = new Map<string, Program>();
    (programs ?? []).forEach((p) => m.set(p.name, p));
    return m;
  }, [programs]);

  const tags = useMemo(() => {
    const set = new Set<string>();
    list.forEach((v) => v.tags.forEach((t) => set.add(t)));
    return Array.from(set).sort();
  }, [list]);

  const totalBounty = useMemo(
    () => list.reduce((sum, v) => sum + (v.bounty ?? 0), 0),
    [list],
  );

  const filtered = useMemo(() => {
    let rows = [...list];
    const q = search.trim().toLowerCase();
    if (q) {
      rows = rows.filter(
        (v) =>
          v.title.toLowerCase().includes(q) ||
          v.asset.toLowerCase().includes(q) ||
          v.tags.some((t) => t.toLowerCase().includes(q)),
      );
    }
    if (severity !== "all") rows = rows.filter((v) => v.severity === severity);
    if (status !== "all") rows = rows.filter((v) => v.submission_status === status);
    if (effectiveProgram !== "all")
      rows = rows.filter((v) => (v.program ?? "") === effectiveProgram);
    if (tag !== "all") rows = rows.filter((v) => v.tags.includes(tag));
    rows.sort(
      (a, b) =>
        SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity] ||
        new Date(b.updated_at).getTime() - new Date(a.updated_at).getTime(),
    );
    return rows;
  }, [list, search, severity, status, effectiveProgram, tag]);

  if (isError) {
    return (
      <div className="text-sm text-destructive p-6">
        Failed to load vulnerabilities.
      </div>
    );
  }

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center gap-2">
        <Input
          placeholder="Search title, asset, tag…"
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          className="max-w-xs"
        />
        <Select value={severity} onValueChange={(v) => v && setSeverity(v as "all" | Severity)}>
          <SelectTrigger className="w-[140px]">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All severities</SelectItem>
            <SelectItem value="critical">critical</SelectItem>
            <SelectItem value="high">high</SelectItem>
            <SelectItem value="medium">medium</SelectItem>
            <SelectItem value="low">low</SelectItem>
            <SelectItem value="info">info</SelectItem>
          </SelectContent>
        </Select>
        <Select
          value={status}
          onValueChange={(v) => v && setStatus(v as "all" | SubmissionStatus)}
        >
          <SelectTrigger className="w-[150px]">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All statuses</SelectItem>
            {SUBMISSION_STATUSES.map((s) => (
              <SelectItem key={s} value={s}>
                {s}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
        {!scoped && programOptions.length > 0 && (
          <Select value={programDropdown} onValueChange={(v) => v && setProgramDropdown(v)}>
            <SelectTrigger className="w-[160px]">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="all">All programs</SelectItem>
              {programOptions.map((p) => (
                <SelectItem key={p} value={p}>
                  {p}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        )}
        {tags.length > 0 && (
          <Select value={tag} onValueChange={(v) => v && setTag(v)}>
            <SelectTrigger className="w-[140px]">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="all">All tags</SelectItem>
              {tags.map((t) => (
                <SelectItem key={t} value={t}>
                  {t}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        )}
        <div className="ml-auto flex items-center gap-2">
          {totalBounty > 0 && (
            <Badge variant="outline" className="text-emerald-400 border-emerald-500/40">
              ${totalBounty.toLocaleString()} earned
            </Badge>
          )}
          <span className="text-xs text-muted-foreground">
            {filtered.length} of {list.length}
          </span>
          <Link
            href="/vulnerabilities/new"
            className={cn(buttonVariants({ size: "sm" }), "gap-1")}
          >
            <Plus className="size-3.5" /> New Vuln
          </Link>
        </div>
      </div>

      <div className="rounded-md border overflow-x-auto">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead className="w-[100px]">Severity</TableHead>
              <TableHead>Title</TableHead>
              <TableHead className="w-[140px]">Program</TableHead>
              <TableHead>Asset</TableHead>
              <TableHead className="w-[110px]">Status</TableHead>
              <TableHead className="w-[100px] text-right">Bounty</TableHead>
              <TableHead className="hidden md:table-cell">Tags</TableHead>
              <TableHead className="w-[120px] text-right">Updated</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {isLoading ? (
              <TableRow>
                <TableCell colSpan={8} className="text-center py-8 text-muted-foreground">
                  Loading…
                </TableCell>
              </TableRow>
            ) : filtered.length === 0 ? (
              <TableRow>
                <TableCell colSpan={8} className="text-center py-12">
                  <Bug className="size-8 mx-auto text-muted-foreground/50 mb-2" />
                  <p className="text-sm text-muted-foreground">
                    {list.length === 0
                      ? "No vulnerabilities yet."
                      : "No vulnerabilities match the filters."}
                  </p>
                  {list.length === 0 && (
                    <Link
                      href="/vulnerabilities/new"
                      className={cn(
                        buttonVariants({ variant: "outline", size: "sm" }),
                        "mt-3 gap-1",
                      )}
                    >
                      <Plus className="size-3.5" /> Create your first
                    </Link>
                  )}
                </TableCell>
              </TableRow>
            ) : (
              filtered.map((v) => {
                const stv = STATUS_VARIANT[v.submission_status] ?? STATUS_VARIANT.wait;
                return (
                  <TableRow
                    key={v.id}
                    className="cursor-pointer hover:bg-muted/50"
                  >
                    <TableCell>
                      <Link href={`/vulnerabilities/${v.id}`} className="block">
                        <SeverityBadge severity={v.severity} />
                      </Link>
                    </TableCell>
                    <TableCell>
                      <Link href={`/vulnerabilities/${v.id}`} className="block font-medium">
                        {v.title}
                      </Link>
                    </TableCell>
                    <TableCell className="text-xs">
                      {v.program ? (
                        <div className="flex items-center gap-1 flex-wrap">
                          <Link
                            href={`/programs/${encodeURIComponent(v.program)}`}
                            className="hover:text-sky-400 hover:underline"
                            onClick={(e) => e.stopPropagation()}
                          >
                            <Badge variant="secondary" className="text-[10px]">
                              {v.program}
                            </Badge>
                          </Link>
                          {(() => {
                            const prog = programByName.get(v.program);
                            if (!prog?.vendor) return null;
                            return (
                              <Badge
                                variant="outline"
                                className={cn(
                                  "text-[9px] uppercase tracking-wider",
                                  VENDOR_VARIANT[prog.vendor.toLowerCase()] ??
                                    "border-border text-muted-foreground",
                                )}
                              >
                                {prog.vendor}
                              </Badge>
                            );
                          })()}
                        </div>
                      ) : (
                        <span className="text-muted-foreground">—</span>
                      )}
                    </TableCell>
                    <TableCell className="font-mono text-xs">
                      {v.asset || <span className="text-muted-foreground">—</span>}
                    </TableCell>
                    <TableCell>
                      <Badge variant="outline" className={cn("text-[10px]", stv.className)}>
                        {stv.label}
                      </Badge>
                    </TableCell>
                    <TableCell className="text-right tabular-nums text-xs">
                      {v.bounty > 0 ? (
                        <span className="text-emerald-400">${v.bounty.toLocaleString()}</span>
                      ) : (
                        <span className="text-muted-foreground">—</span>
                      )}
                    </TableCell>
                    <TableCell className="hidden md:table-cell">
                      <div className="flex flex-wrap gap-1">
                        {v.tags.slice(0, 3).map((t) => (
                          <Badge key={t} variant="secondary" className="text-[10px]">
                            {t}
                          </Badge>
                        ))}
                        {v.tags.length > 3 && (
                          <span className="text-xs text-muted-foreground">
                            +{v.tags.length - 3}
                          </span>
                        )}
                      </div>
                    </TableCell>
                    <TableCell className="text-right tabular-nums text-xs text-muted-foreground">
                      {formatRelative(v.updated_at)}
                    </TableCell>
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
