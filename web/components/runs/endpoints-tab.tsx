"use client";

import { useMemo, useState } from "react";
import { ExternalLink, Sparkles } from "lucide-react";
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
import { useRunEndpoints } from "@/lib/api/hooks";
import { HostLink } from "@/components/runs/host-link";
import { hostnameFromURL, normalizeHostname } from "@/lib/host";
import { cn } from "@/lib/utils";

const RENDER_CAP = 200;

const METHOD_VARIANT: Record<string, string> = {
  GET: "border-sky-500/40 text-sky-400",
  POST: "border-emerald-500/40 text-emerald-400",
  PUT: "border-amber-500/40 text-amber-300",
  PATCH: "border-amber-500/40 text-amber-300",
  DELETE: "border-destructive/50 text-destructive",
  OPTIONS: "border-border text-muted-foreground",
};

// Param names that often signal IDOR / SSRF candidates. Used to highlight
// "interesting" rows so the analyst can pivot quickly.
const SUSPICIOUS_PARAMS = [
  "id",
  "user",
  "userid",
  "uid",
  "account",
  "url",
  "redirect",
  "callback",
  "next",
  "return",
  "uri",
  "target",
];

function suspicionMarkers(url: string): string[] {
  try {
    const u = new URL(url);
    const params = [...u.searchParams.keys()].map((p) => p.toLowerCase());
    return params.filter((p) =>
      SUSPICIOUS_PARAMS.some((s) => p === s || p.includes(s)),
    );
  } catch {
    return [];
  }
}

function statusColor(code: number | undefined): string {
  if (!code) return "text-muted-foreground";
  if (code >= 200 && code < 300) return "text-emerald-400";
  if (code >= 300 && code < 400) return "text-sky-400";
  if (code >= 400 && code < 500) return "text-amber-300";
  return "text-destructive";
}

export function EndpointsTab({
  runId,
  hostFilter,
}: {
  runId: string;
  hostFilter?: string;
}) {
  const { data, isLoading, isError } = useRunEndpoints(runId);
  const [search, setSearch] = useState("");
  const [method, setMethod] = useState<string>("all");
  const [statusGroup, setStatusGroup] = useState<string>("all");
  const [interesting, setInteresting] = useState(false);

  const all = useMemo(() => {
    let list = data ?? [];
    if (hostFilter) {
      const canon = normalizeHostname(hostFilter);
      list = list.filter((e) => hostnameFromURL(e.url) === canon);
    }
    return list;
  }, [data, hostFilter]);

  const methodOptions = useMemo(() => {
    const set = new Set(all.map((e) => e.method));
    return [...set].sort();
  }, [all]);

  const filtered = useMemo(() => {
    const q = search.trim().toLowerCase();
    return all.filter((e) => {
      if (method !== "all" && e.method !== method) return false;
      if (statusGroup !== "all") {
        const code = e.status_code ?? 0;
        const grp =
          code >= 200 && code < 300
            ? "2xx"
            : code >= 300 && code < 400
              ? "3xx"
              : code >= 400 && code < 500
                ? "4xx"
                : code >= 500
                  ? "5xx"
                  : "?";
        if (grp !== statusGroup) return false;
      }
      if (interesting && suspicionMarkers(e.url).length === 0) return false;
      if (q) {
        if (!e.url.toLowerCase().includes(q)) return false;
      }
      return true;
    });
  }, [all, search, method, statusGroup, interesting]);

  const visible = filtered.slice(0, RENDER_CAP);

  if (isError) {
    return (
      <div className="text-sm text-destructive p-6">
        Failed to load endpoints.
      </div>
    );
  }

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center gap-2">
        <Input
          placeholder="Search URL…"
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          className="max-w-xs font-mono text-xs"
        />
        <Select value={method} onValueChange={(v) => v && setMethod(v)}>
          <SelectTrigger className="w-[120px]">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All methods</SelectItem>
            {methodOptions.map((m) => (
              <SelectItem key={m} value={m}>
                {m}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
        <Select value={statusGroup} onValueChange={(v) => v && setStatusGroup(v)}>
          <SelectTrigger className="w-[120px]">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All status</SelectItem>
            <SelectItem value="2xx">2xx</SelectItem>
            <SelectItem value="3xx">3xx</SelectItem>
            <SelectItem value="4xx">4xx</SelectItem>
            <SelectItem value="5xx">5xx</SelectItem>
          </SelectContent>
        </Select>
        <button
          type="button"
          onClick={() => setInteresting((s) => !s)}
          className={cn(
            "inline-flex items-center gap-1 rounded border px-2 h-7 text-xs",
            interesting
              ? "border-amber-500/40 text-amber-300 bg-amber-500/10"
              : "border-border text-muted-foreground hover:bg-muted",
          )}
        >
          <Sparkles className="size-3" />
          Interesting only
        </button>
        <div className="ml-auto text-xs text-muted-foreground">
          {filtered.length > RENDER_CAP ? (
            <span>
              showing first {RENDER_CAP} of {filtered.length}
              <span className="text-foreground/60"> — refine filters</span>
            </span>
          ) : (
            <>
              {filtered.length} / {all.length} endpoints
            </>
          )}
        </div>
      </div>

      <div className="rounded-md border overflow-x-auto">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead className="w-[80px]">Method</TableHead>
              <TableHead className="w-[80px]">Status</TableHead>
              <TableHead>URL</TableHead>
              <TableHead className="w-[180px]">Content-Type</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {isLoading ? (
              <TableRow>
                <TableCell colSpan={4} className="text-center py-8 text-muted-foreground">
                  Loading endpoints…
                </TableCell>
              </TableRow>
            ) : visible.length === 0 ? (
              <TableRow>
                <TableCell colSpan={4} className="text-center py-8 text-muted-foreground">
                  {all.length === 0
                    ? "No endpoints — discover stage may not have run."
                    : "No endpoints match the filters."}
                </TableCell>
              </TableRow>
            ) : (
              visible.map((ep, i) => {
                const markers = suspicionMarkers(ep.url);
                return (
                  <TableRow
                    key={`${ep.method}-${ep.url}-${i}`}
                    className="hover:bg-muted/50"
                  >
                    <TableCell>
                      <Badge
                        variant="outline"
                        className={cn(
                          "text-[10px] font-mono tabular-nums",
                          METHOD_VARIANT[ep.method] ??
                            METHOD_VARIANT.OPTIONS,
                        )}
                      >
                        {ep.method}
                      </Badge>
                    </TableCell>
                    <TableCell className={cn("text-xs tabular-nums", statusColor(ep.status_code))}>
                      {ep.status_code ?? "—"}
                    </TableCell>
                    <TableCell className="font-mono text-xs">
                      <div className="flex items-center gap-2 min-w-0">
                        <HostLink
                          url={ep.url}
                          runId={runId}
                          className="truncate"
                        />
                        <a
                          href={ep.url}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="text-muted-foreground hover:text-sky-400 shrink-0"
                          onClick={(e) => e.stopPropagation()}
                          title="Open in new tab"
                        >
                          <ExternalLink className="size-3" />
                        </a>
                        {markers.length > 0 && (
                          <div className="flex gap-1 shrink-0">
                            {markers.slice(0, 3).map((m) => (
                              <Badge
                                key={m}
                                variant="outline"
                                className="text-[9px] border-amber-500/40 text-amber-300"
                              >
                                {m}
                              </Badge>
                            ))}
                          </div>
                        )}
                      </div>
                    </TableCell>
                    <TableCell className="text-xs text-muted-foreground">
                      {ep.content_type || "—"}
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
