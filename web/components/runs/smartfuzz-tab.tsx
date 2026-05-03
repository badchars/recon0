"use client";

import { Fragment, useMemo, useState } from "react";
import { ChevronDown, ChevronRight, ExternalLink } from "lucide-react";
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
import { useRunSmartfuzz } from "@/lib/api/hooks";
import { SeverityBadge } from "@/components/severity-badge";
import { HostLink } from "@/components/runs/host-link";
import { hostnameFromURL, normalizeHostname } from "@/lib/host";
import { cn } from "@/lib/utils";

export function SmartfuzzTab({
  runId,
  hostFilter,
}: {
  runId: string;
  hostFilter?: string;
}) {
  const { data, isLoading, isError } = useRunSmartfuzz(runId);
  const [search, setSearch] = useState("");
  const [severity, setSeverity] = useState<string>("all");
  const [template, setTemplate] = useState<string>("all");
  const [expanded, setExpanded] = useState<number | null>(null);

  const all = useMemo(() => {
    let list = data ?? [];
    if (hostFilter) {
      const canon = normalizeHostname(hostFilter);
      list = list.filter((s) => hostnameFromURL(s.host) === canon);
    }
    return list;
  }, [data, hostFilter]);

  const severityOptions = useMemo(() => {
    const set = new Set(all.map((s) => s.severity));
    return [...set].sort();
  }, [all]);

  const templateOptions = useMemo(() => {
    const set = new Set(all.map((s) => s["template-id"]));
    return [...set].sort();
  }, [all]);

  const filtered = useMemo(() => {
    const q = search.trim().toLowerCase();
    return all.filter((s) => {
      if (severity !== "all" && s.severity !== severity) return false;
      if (template !== "all" && s["template-id"] !== template) return false;
      if (q) {
        const hay = [s.name, s.host, s["matched-at"], s.description, s["template-id"]]
          .filter(Boolean)
          .join(" ")
          .toLowerCase();
        if (!hay.includes(q)) return false;
      }
      return true;
    });
  }, [all, search, severity, template]);

  if (isError) {
    return (
      <div className="text-sm text-destructive p-6">
        Failed to load smartfuzz findings.
      </div>
    );
  }

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center gap-2">
        <Input
          placeholder="Search name, host, matched-at…"
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          className="max-w-xs"
        />
        <Select value={severity} onValueChange={(v) => v && setSeverity(v)}>
          <SelectTrigger className="w-[140px]">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All severities</SelectItem>
            {severityOptions.map((s) => (
              <SelectItem key={s} value={s}>
                {s}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
        <Select value={template} onValueChange={(v) => v && setTemplate(v)}>
          <SelectTrigger className="w-[220px]">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All templates</SelectItem>
            {templateOptions.map((t) => (
              <SelectItem key={t} value={t}>
                {t}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
        <div className="ml-auto text-xs text-muted-foreground">
          {filtered.length} / {all.length} findings
        </div>
      </div>

      <div className="rounded-md border overflow-x-auto">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead className="w-[32px]" />
              <TableHead className="w-[100px]">Severity</TableHead>
              <TableHead>Name</TableHead>
              <TableHead>Matched at</TableHead>
              <TableHead className="w-[180px]">Template</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {isLoading ? (
              <TableRow>
                <TableCell colSpan={5} className="text-center py-8 text-muted-foreground">
                  Loading smartfuzz…
                </TableCell>
              </TableRow>
            ) : filtered.length === 0 ? (
              <TableRow>
                <TableCell colSpan={5} className="text-center py-8 text-muted-foreground">
                  {all.length === 0
                    ? "No smartfuzz findings — vuln stage may not have run."
                    : "No findings match the filters."}
                </TableCell>
              </TableRow>
            ) : (
              filtered.map((s, i) => {
                const isExpanded = expanded === i;
                return (
                  <Fragment key={`${s["template-id"]}-${i}`}>
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
                        <SeverityBadge severity={s.severity} />
                      </TableCell>
                      <TableCell className="text-xs">
                        <div className="font-medium">{s.name}</div>
                      </TableCell>
                      <TableCell className="font-mono text-xs">
                        <HostLink
                          url={s["matched-at"]}
                          runId={runId}
                          className="block truncate max-w-2xl"
                        />
                      </TableCell>
                      <TableCell>
                        <Badge variant="secondary" className="text-[10px] font-mono">
                          {s["template-id"]}
                        </Badge>
                      </TableCell>
                    </TableRow>
                    {isExpanded && (
                      <TableRow className="hover:bg-transparent">
                        <TableCell colSpan={5} className="bg-muted/20 p-4">
                          <div className="space-y-2 text-xs">
                            <div className="text-sm font-medium">{s.name}</div>
                            {s.description && (
                              <div className="text-muted-foreground">{s.description}</div>
                            )}
                            <DetailRow label="Host">
                              <a
                                href={s.host}
                                target="_blank"
                                rel="noopener noreferrer"
                                className="text-sky-400 hover:underline break-all inline-flex items-center gap-1"
                              >
                                {s.host} <ExternalLink className="size-3" />
                              </a>
                            </DetailRow>
                            <DetailRow label="Matched">
                              <a
                                href={s["matched-at"]}
                                target="_blank"
                                rel="noopener noreferrer"
                                className="text-sky-400 hover:underline break-all inline-flex items-center gap-1"
                              >
                                {s["matched-at"]} <ExternalLink className="size-3" />
                              </a>
                            </DetailRow>
                            <DetailRow label="Template">
                              <code className="font-mono text-[10px]">{s["template-id"]}</code>
                            </DetailRow>
                            {s.evidence && (
                              <DetailRow label="Evidence">
                                <pre className="font-mono text-[10px] bg-background border rounded p-2 overflow-auto max-h-60 break-all whitespace-pre-wrap">
                                  {s.evidence}
                                </pre>
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
      <span className="flex-1 min-w-0">{children}</span>
    </div>
  );
}
