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
import { useRunInvestigations } from "@/lib/api/hooks";
import { SeverityBadge } from "@/components/severity-badge";
import { HostLink } from "@/components/runs/host-link";
import { hostnameFromURL, normalizeHostname } from "@/lib/host";
import { cn } from "@/lib/utils";
import type { Investigation, Severity } from "@/lib/api/types";

const RENDER_CAP = 200;

const CONFIDENCE_VARIANT: Record<string, string> = {
  high: "border-emerald-500/40 text-emerald-400",
  medium: "border-sky-500/40 text-sky-400",
  low: "border-border text-muted-foreground",
};

export function InvestigationsTab({
  runId,
  hostFilter,
}: {
  runId: string;
  hostFilter?: string;
}) {
  const { data, isLoading, isError } = useRunInvestigations(runId);
  const [search, setSearch] = useState("");
  const [severity, setSeverity] = useState<"all" | Severity>("all");
  const [vulnType, setVulnType] = useState<string>("all");
  const [confidence, setConfidence] = useState<string>("all");
  const [expanded, setExpanded] = useState<string | null>(null);

  const all: Investigation[] = useMemo(() => {
    let list = data ?? [];
    if (hostFilter) {
      const canon = normalizeHostname(hostFilter);
      list = list.filter((i) => hostnameFromURL(i.found_at?.url) === canon);
    }
    return list;
  }, [data, hostFilter]);

  const vulnTypeOptions = useMemo(() => {
    const set = new Set(all.map((i) => i.vuln_type));
    return [...set].sort();
  }, [all]);

  const filtered = useMemo(() => {
    const q = search.trim().toLowerCase();
    return all.filter((i) => {
      if (severity !== "all" && i.severity !== severity) return false;
      if (vulnType !== "all" && i.vuln_type !== vulnType) return false;
      if (confidence !== "all" && i.confidence !== confidence) return false;
      if (q) {
        const hay = [i.title, i.description, i.found_at?.url]
          .filter(Boolean)
          .join(" ")
          .toLowerCase();
        if (!hay.includes(q)) return false;
      }
      return true;
    });
  }, [all, search, severity, vulnType, confidence]);

  const visible = filtered.slice(0, RENDER_CAP);

  if (isError) {
    return (
      <div className="text-sm text-destructive p-6">
        Failed to load investigations.
      </div>
    );
  }

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center gap-2">
        <Input
          placeholder="Search title, description, url…"
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
            <SelectItem value="all">All severities</SelectItem>
            <SelectItem value="critical">critical</SelectItem>
            <SelectItem value="high">high</SelectItem>
            <SelectItem value="medium">medium</SelectItem>
            <SelectItem value="low">low</SelectItem>
            <SelectItem value="info">info</SelectItem>
          </SelectContent>
        </Select>
        <Select value={vulnType} onValueChange={(v) => v && setVulnType(v)}>
          <SelectTrigger className="w-[180px]">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All types</SelectItem>
            {vulnTypeOptions.map((t) => (
              <SelectItem key={t} value={t}>
                {t}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
        <Select value={confidence} onValueChange={(v) => v && setConfidence(v)}>
          <SelectTrigger className="w-[140px]">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All confidence</SelectItem>
            <SelectItem value="high">high</SelectItem>
            <SelectItem value="medium">medium</SelectItem>
            <SelectItem value="low">low</SelectItem>
          </SelectContent>
        </Select>
        <div className="ml-auto text-xs text-muted-foreground">
          {filtered.length > RENDER_CAP ? (
            <span>
              showing first {RENDER_CAP} of {filtered.length}
              <span className="text-foreground/60"> — refine filters</span>
            </span>
          ) : (
            <>
              {filtered.length} / {all.length} investigations
            </>
          )}
        </div>
      </div>

      <div className="rounded-md border overflow-x-auto">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead className="w-[32px]" />
              <TableHead className="w-[100px]">Severity</TableHead>
              <TableHead className="w-[120px]">Type</TableHead>
              <TableHead className="w-[100px]">Confidence</TableHead>
              <TableHead>Title</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {isLoading ? (
              <TableRow>
                <TableCell colSpan={5} className="text-center py-8 text-muted-foreground">
                  Loading investigations…
                </TableCell>
              </TableRow>
            ) : visible.length === 0 ? (
              <TableRow>
                <TableCell colSpan={5} className="text-center py-8 text-muted-foreground">
                  {all.length === 0
                    ? "No investigations — collect stage may not have run."
                    : "No investigations match the filters."}
                </TableCell>
              </TableRow>
            ) : (
              visible.map((inv) => {
                const isExpanded = expanded === inv.id;
                return (
                  <Fragment key={inv.id}>
                    <TableRow
                      className={cn(
                        "cursor-pointer hover:bg-muted/50",
                        isExpanded && "bg-muted/40 border-b-0",
                      )}
                      onClick={() => setExpanded(isExpanded ? null : inv.id)}
                    >
                      <TableCell>
                        {isExpanded ? (
                          <ChevronDown className="size-4 text-muted-foreground" />
                        ) : (
                          <ChevronRight className="size-4 text-muted-foreground" />
                        )}
                      </TableCell>
                      <TableCell>
                        <SeverityBadge severity={inv.severity} />
                      </TableCell>
                      <TableCell>
                        <Badge variant="secondary" className="text-[10px] font-mono">
                          {inv.vuln_type}
                        </Badge>
                      </TableCell>
                      <TableCell>
                        <Badge
                          variant="outline"
                          className={cn(
                            "text-[10px]",
                            CONFIDENCE_VARIANT[inv.confidence] ??
                              CONFIDENCE_VARIANT.low,
                          )}
                        >
                          {inv.confidence}
                        </Badge>
                      </TableCell>
                      <TableCell className="text-xs">
                        <div className="truncate max-w-2xl">{inv.title}</div>
                      </TableCell>
                    </TableRow>
                    {isExpanded && (
                      <TableRow className="hover:bg-transparent">
                        <TableCell colSpan={5} className="bg-muted/20 p-4">
                          <div className="space-y-3 text-xs">
                            <div className="text-sm font-medium">{inv.title}</div>
                            {inv.description && (
                              <div className="text-muted-foreground whitespace-pre-wrap">
                                {inv.description}
                              </div>
                            )}
                            {inv.found_at?.url && (
                              <DetailRow label="URL">
                                <span className="inline-flex items-center gap-2 flex-wrap">
                                  <a
                                    href={inv.found_at.url}
                                    target="_blank"
                                    rel="noopener noreferrer"
                                    className="inline-flex items-center gap-1 text-sky-400 hover:underline break-all"
                                  >
                                    {inv.found_at.url}
                                    <ExternalLink className="size-3 shrink-0" />
                                  </a>
                                  <HostLink
                                    url={inv.found_at.url}
                                    runId={runId}
                                    display="↪ host details"
                                    className="text-[10px] text-muted-foreground"
                                  />
                                </span>
                              </DetailRow>
                            )}
                            {inv.question && (
                              <DetailRow label="Verify">
                                <span className="italic">{inv.question}</span>
                              </DetailRow>
                            )}
                            {inv.verify_steps != null && (
                              <DetailRow label="Steps">
                                <pre className="font-mono text-[10px] bg-background border rounded p-2 overflow-auto max-h-40">
                                  {typeof inv.verify_steps === "string"
                                    ? inv.verify_steps
                                    : JSON.stringify(inv.verify_steps, null, 2)}
                                </pre>
                              </DetailRow>
                            )}
                            {inv.evidence != null && (
                              <DetailRow label="Evidence">
                                <pre className="font-mono text-[10px] bg-background border rounded p-2 overflow-auto max-h-40">
                                  {typeof inv.evidence === "string"
                                    ? inv.evidence
                                    : JSON.stringify(inv.evidence, null, 2)}
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
