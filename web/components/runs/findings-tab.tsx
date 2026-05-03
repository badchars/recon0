"use client";

import { Fragment, useMemo, useState } from "react";
import { ChevronDown, ChevronRight } from "lucide-react";
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
import { useRunFindings } from "@/lib/api/hooks";
import { SeverityBadge } from "@/components/severity-badge";
import { HostLink } from "@/components/runs/host-link";
import { hostnameFromURL, normalizeHostname } from "@/lib/host";
import { cn } from "@/lib/utils";
import type { Severity } from "@/lib/api/types";

const SEVERITY_OPTIONS: ("all" | Severity)[] = [
  "all",
  "critical",
  "high",
  "medium",
  "low",
  "info",
];

export function FindingsTab({
  runId,
  hostFilter,
}: {
  runId: string;
  hostFilter?: string;
}) {
  const { data, isLoading, isError } = useRunFindings(runId);
  const [search, setSearch] = useState("");
  const [severity, setSeverity] = useState<"all" | Severity>("all");
  const [rule, setRule] = useState<string>("all");
  const [source, setSource] = useState<string>("all");
  const [expanded, setExpanded] = useState<number | null>(null);

  const findings = useMemo(() => {
    let list = data ?? [];
    if (hostFilter) {
      const canon = normalizeHostname(hostFilter);
      list = list.filter((f) => hostnameFromURL(f.url) === canon);
    }
    return list;
  }, [data, hostFilter]);

  const ruleOptions = useMemo(() => {
    const set = new Set(findings.map((f) => f.rule_id));
    return [...set].sort();
  }, [findings]);

  const sourceOptions = useMemo(() => {
    const set = new Set(findings.map((f) => f.source));
    return [...set].sort();
  }, [findings]);

  const filtered = useMemo(() => {
    const q = search.trim().toLowerCase();
    return findings.filter((f) => {
      if (severity !== "all" && f.severity !== severity) return false;
      if (rule !== "all" && f.rule_id !== rule) return false;
      if (source !== "all" && f.source !== source) return false;
      if (q) {
        const hay = [f.rule_name, f.value, f.url, f.file].join(" ").toLowerCase();
        if (!hay.includes(q)) return false;
      }
      return true;
    });
  }, [findings, search, severity, rule, source]);

  if (isError) {
    return (
      <div className="text-sm text-destructive p-6">
        Failed to load findings.
      </div>
    );
  }

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center gap-2">
        <Input
          placeholder="Search rule, value, url…"
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          className="max-w-xs"
        />
        <Select
          value={severity}
          onValueChange={(v) => v && setSeverity(v as "all" | Severity)}
        >
          <SelectTrigger className="w-[140px]">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            {SEVERITY_OPTIONS.map((s) => (
              <SelectItem key={s} value={s}>
                {s === "all" ? "All severities" : s}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
        <Select value={rule} onValueChange={(v) => v && setRule(v)}>
          <SelectTrigger className="w-[200px]">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All rules</SelectItem>
            {ruleOptions.map((r) => (
              <SelectItem key={r} value={r}>
                {r}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
        <Select value={source} onValueChange={(v) => v && setSource(v)}>
          <SelectTrigger className="w-[150px]">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All sources</SelectItem>
            {sourceOptions.map((s) => (
              <SelectItem key={s} value={s}>
                {s}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
        <div className="ml-auto text-xs text-muted-foreground">
          {filtered.length} / {findings.length} findings
        </div>
      </div>

      <div className="rounded-md border overflow-x-auto">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead className="w-[32px]" />
              <TableHead className="w-[100px]">Severity</TableHead>
              <TableHead>Rule</TableHead>
              <TableHead>Value</TableHead>
              <TableHead className="w-[140px]">Source</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {isLoading ? (
              <TableRow>
                <TableCell colSpan={5} className="text-center py-8 text-muted-foreground">
                  Loading findings…
                </TableCell>
              </TableRow>
            ) : filtered.length === 0 ? (
              <TableRow>
                <TableCell colSpan={5} className="text-center py-8 text-muted-foreground">
                  {findings.length === 0
                    ? "No findings — analyze stage may not have run."
                    : "No findings match the filters."}
                </TableCell>
              </TableRow>
            ) : (
              filtered.map((f, i) => {
                const isExpanded = expanded === i;
                return (
                  <Fragment key={`${f.rule_id}-${i}`}>
                    <TableRow
                      className={cn(
                        "cursor-pointer hover:bg-muted/50",
                        isExpanded && "bg-muted/40 border-b-0",
                      )}
                      onClick={() => setExpanded(isExpanded ? null : i)}
                    >
                      <TableCell>
                        {isExpanded ? (
                          <ChevronDown className="size-4 text-muted-foreground" />
                        ) : (
                          <ChevronRight className="size-4 text-muted-foreground" />
                        )}
                      </TableCell>
                      <TableCell>
                        <SeverityBadge severity={f.severity} />
                      </TableCell>
                      <TableCell className="text-xs">
                        <div className="font-medium">{f.rule_name}</div>
                        <div className="text-muted-foreground font-mono text-[10px]">
                          {f.rule_id}
                        </div>
                      </TableCell>
                      <TableCell className="font-mono text-xs">
                        <div className="truncate max-w-md">{f.value}</div>
                      </TableCell>
                      <TableCell>
                        <Badge variant="secondary" className="text-[10px]">
                          {f.source}
                        </Badge>
                      </TableCell>
                    </TableRow>
                    {isExpanded && (
                      <TableRow className="hover:bg-transparent">
                        <TableCell colSpan={5} className="bg-muted/20 p-4">
                          <div className="space-y-2 text-xs">
                            <DetailRow label="Rule">
                              <span className="font-medium">{f.rule_name}</span>
                              <span className="text-muted-foreground font-mono ml-2">
                                ({f.rule_id})
                              </span>
                            </DetailRow>
                            <DetailRow label="Value">
                              <code className="font-mono break-all bg-background border rounded px-2 py-1 inline-block">
                                {f.value}
                              </code>
                            </DetailRow>
                            <DetailRow label="Source">{f.source}</DetailRow>
                            {f.file && <DetailRow label="File">{f.file}</DetailRow>}
                            {f.url && (
                              <DetailRow label="URL">
                                <span className="inline-flex items-center gap-2 flex-wrap">
                                  <a
                                    href={f.url}
                                    target="_blank"
                                    rel="noopener noreferrer"
                                    className="text-sky-400 hover:underline break-all"
                                  >
                                    {f.url}
                                  </a>
                                  <HostLink
                                    url={f.url}
                                    runId={runId}
                                    display="↪ host details"
                                    className="text-[10px] text-muted-foreground"
                                  />
                                </span>
                              </DetailRow>
                            )}
                          </div>
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

function DetailRow({
  label,
  children,
}: {
  label: string;
  children: React.ReactNode;
}) {
  return (
    <div className="flex items-start gap-3 min-w-0">
      <span className="w-20 text-muted-foreground shrink-0 text-[11px] uppercase tracking-wider">
        {label}
      </span>
      <span className="flex-1 min-w-0 break-words">{children}</span>
    </div>
  );
}
