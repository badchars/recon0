"use client";

import { Fragment, useMemo, useState } from "react";
import { ChevronDown, ChevronRight, Globe, Lock, Server } from "lucide-react";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
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
import { useHostAnnotations, useRunHosts } from "@/lib/api/hooks";
import { cn } from "@/lib/utils";
import { normalizeHostname } from "@/lib/host";
import { HostSummaryRow } from "@/components/runs/host-summary-row";
import { ReviewBadge } from "@/components/runs/review-badge";
import type { ReviewStatus } from "@/lib/api/types";

type StatusGroup = "all" | "2xx" | "3xx" | "4xx" | "5xx";

function statusGroup(code: number | undefined): StatusGroup {
  if (!code) return "all";
  if (code >= 200 && code < 300) return "2xx";
  if (code >= 300 && code < 400) return "3xx";
  if (code >= 400 && code < 500) return "4xx";
  return "5xx";
}

function statusClass(code: number | undefined): string {
  switch (statusGroup(code)) {
    case "2xx":
      return "border-emerald-500/40 text-emerald-400";
    case "3xx":
      return "border-sky-500/40 text-sky-400";
    case "4xx":
      return "border-amber-500/40 text-amber-300";
    case "5xx":
      return "border-destructive/40 text-destructive";
    default:
      return "border-border text-muted-foreground";
  }
}

export function HostsTab({ runId }: { runId: string }) {
  const { data, isLoading, isError } = useRunHosts(runId);
  const { data: annotations } = useHostAnnotations();
  const [search, setSearch] = useState("");
  const [status, setStatus] = useState<StatusGroup>("all");
  const [tech, setTech] = useState<string>("all");
  const [cdn, setCdn] = useState<string>("all");
  const [review, setReview] = useState<"all" | ReviewStatus>("all");
  const [expandedKey, setExpandedKey] = useState<string | null>(null);

  const hosts = useMemo(() => data ?? [], [data]);

  const reviewOf = (h: { host?: string; url: string }): ReviewStatus => {
    const key = normalizeHostname(h.host || h.url);
    return annotations?.[key]?.review_status ?? "not_reviewed";
  };

  const techOptions = useMemo(() => {
    const counts = new Map<string, number>();
    for (const h of hosts) {
      for (const t of h.tech ?? []) counts.set(t, (counts.get(t) ?? 0) + 1);
    }
    return [...counts.entries()]
      .sort((a, b) => b[1] - a[1])
      .slice(0, 30)
      .map(([t]) => t);
  }, [hosts]);

  const cdnOptions = useMemo(() => {
    const set = new Set<string>();
    for (const h of hosts) {
      const v = h.cdn_name?.trim();
      if (v) set.add(v);
    }
    return [...set].sort();
  }, [hosts]);

  const filtered = useMemo(() => {
    const q = search.trim().toLowerCase();
    return hosts.filter((h) => {
      if (q) {
        const hay = [h.url, h.host, h.title, ...(h.tech ?? [])]
          .filter(Boolean)
          .join(" ")
          .toLowerCase();
        if (!hay.includes(q)) return false;
      }
      if (status !== "all" && statusGroup(h.status_code) !== status) return false;
      if (tech !== "all" && !(h.tech ?? []).includes(tech)) return false;
      if (cdn !== "all" && (h.cdn_name ?? "") !== cdn) return false;
      if (review !== "all") {
        const hostKey = normalizeHostname(h.host || h.url);
        const cur = annotations?.[hostKey]?.review_status ?? "not_reviewed";
        if (cur !== review) return false;
      }
      return true;
    });
  }, [hosts, search, status, tech, cdn, review, annotations]);

  if (isError) {
    return (
      <div className="text-sm text-destructive p-6">
        Failed to load hosts data.
      </div>
    );
  }

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center gap-2">
        <Input
          placeholder="Search URL, title, tech…"
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          className="max-w-xs"
        />
        <Select value={status} onValueChange={(v) => v && setStatus(v as StatusGroup)}>
          <SelectTrigger className="w-[120px]">
            <SelectValue placeholder="Status" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All status</SelectItem>
            <SelectItem value="2xx">2xx</SelectItem>
            <SelectItem value="3xx">3xx</SelectItem>
            <SelectItem value="4xx">4xx</SelectItem>
            <SelectItem value="5xx">5xx</SelectItem>
          </SelectContent>
        </Select>
        <Select value={tech} onValueChange={(v) => v && setTech(v)}>
          <SelectTrigger className="w-[180px]">
            <SelectValue placeholder="Tech" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All tech</SelectItem>
            {techOptions.map((t) => (
              <SelectItem key={t} value={t}>
                {t}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
        <Select value={cdn} onValueChange={(v) => v && setCdn(v)}>
          <SelectTrigger className="w-[150px]">
            <SelectValue placeholder="CDN" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All CDN</SelectItem>
            {cdnOptions.map((c) => (
              <SelectItem key={c} value={c}>
                {c}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
        <Select value={review} onValueChange={(v) => v && setReview(v as "all" | ReviewStatus)}>
          <SelectTrigger className="w-[150px]">
            <SelectValue placeholder="Review" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All review</SelectItem>
            <SelectItem value="not_reviewed">Not reviewed</SelectItem>
            <SelectItem value="reviewing">Reviewing</SelectItem>
            <SelectItem value="reviewed">Reviewed</SelectItem>
          </SelectContent>
        </Select>
        <div className="ml-auto text-xs text-muted-foreground">
          {filtered.length} / {hosts.length} hosts
        </div>
      </div>

      <div className="rounded-md border overflow-x-auto">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead className="w-[32px]" />
              <TableHead className="w-[110px]">Review</TableHead>
              <TableHead className="w-[80px]">Status</TableHead>
              <TableHead>URL</TableHead>
              <TableHead>Tech</TableHead>
              <TableHead className="w-[140px]">Server</TableHead>
              <TableHead className="w-[100px]">CDN</TableHead>
              <TableHead className="w-[80px] text-right">TLS</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {isLoading ? (
              <TableRow>
                <TableCell colSpan={8} className="text-center py-8 text-muted-foreground">
                  Loading hosts…
                </TableCell>
              </TableRow>
            ) : filtered.length === 0 ? (
              <TableRow>
                <TableCell colSpan={8} className="text-center py-8 text-muted-foreground">
                  {hosts.length === 0
                    ? "No hosts data — probe stage may not have run."
                    : "No hosts match the filters."}
                </TableCell>
              </TableRow>
            ) : (
              filtered.map((h, i) => {
                const key = `${h.url}-${i}`;
                const expanded = expandedKey === key;
                return (
                  <Fragment key={key}>
                    <TableRow
                      className={cn(
                        "cursor-pointer hover:bg-muted/50",
                        expanded && "bg-muted/40 border-b-0",
                      )}
                      onClick={() => setExpandedKey(expanded ? null : key)}
                    >
                      <TableCell>
                        {expanded ? (
                          <ChevronDown className="size-4 text-muted-foreground" />
                        ) : (
                          <ChevronRight className="size-4 text-muted-foreground" />
                        )}
                      </TableCell>
                      <TableCell>
                        <ReviewBadge status={reviewOf(h)} />
                      </TableCell>
                      <TableCell>
                        <Badge variant="outline" className={cn("tabular-nums", statusClass(h.status_code))}>
                          {h.status_code ?? "—"}
                        </Badge>
                      </TableCell>
                      <TableCell className="font-mono text-xs">
                        <div className="flex items-center gap-1.5">
                          <Globe className="size-3 shrink-0 text-muted-foreground" />
                          <span className="truncate">{h.url}</span>
                        </div>
                        {h.title && (
                          <div className="text-[11px] text-muted-foreground truncate">
                            {h.title}
                          </div>
                        )}
                      </TableCell>
                      <TableCell>
                        <div className="flex flex-wrap gap-1">
                          {(h.tech ?? []).slice(0, 3).map((t) => (
                            <Badge key={t} variant="secondary" className="text-[10px]">
                              {t}
                            </Badge>
                          ))}
                          {(h.tech ?? []).length > 3 && (
                            <span className="text-xs text-muted-foreground">
                              +{(h.tech ?? []).length - 3}
                            </span>
                          )}
                        </div>
                      </TableCell>
                      <TableCell className="text-xs">
                        {h.webserver ? (
                          <span className="inline-flex items-center gap-1">
                            <Server className="size-3 text-muted-foreground" />
                            {h.webserver}
                          </span>
                        ) : (
                          <span className="text-muted-foreground">—</span>
                        )}
                      </TableCell>
                      <TableCell className="text-xs">
                        {h.cdn_name || <span className="text-muted-foreground">—</span>}
                      </TableCell>
                      <TableCell className="text-right">
                        {h.tls?.tls_version ? (
                          <span className="inline-flex items-center gap-1 text-[11px] text-emerald-400">
                            <Lock className="size-3" />
                            {h.tls.tls_version.replace("tls", "TLS ")}
                          </span>
                        ) : (
                          <span className="text-muted-foreground text-xs">—</span>
                        )}
                      </TableCell>
                    </TableRow>
                    {expanded && (
                      <TableRow className="hover:bg-transparent">
                        <TableCell colSpan={8} className="bg-muted/20 p-0">
                          <HostSummaryRow runId={runId} host={h} />
                        </TableCell>
                      </TableRow>
                    )}
                  </Fragment>
                );
              })
            )}
          </TableBody>
        </Table>
      </div>
    </div>
  );
}
