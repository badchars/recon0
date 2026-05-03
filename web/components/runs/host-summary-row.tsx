"use client";

import Link from "next/link";
import { useMemo } from "react";
import { ArrowRight, ExternalLink, Lock, Server } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { buttonVariants } from "@/components/ui/button";
import {
  useRunEndpoints,
  useRunFindings,
  useRunInvestigations,
  useRunSmartfuzz,
} from "@/lib/api/hooks";
import { hostnameFromURL, normalizeHostname } from "@/lib/host";
import { cn } from "@/lib/utils";
import type { Host } from "@/lib/api/types";
import { HostAnnotationEditor } from "@/components/runs/host-annotation-editor";

// Inline host summary rendered as an expanded sub-row inside the Hosts
// table. Drops the Sheet wrapper — keeping the user in the table context
// works much better at wide widths and avoids clipping the detail panel.
export function HostSummaryRow({
  runId,
  host,
}: {
  runId: string;
  host: Host;
}) {
  const findings = useRunFindings(runId);
  const investigations = useRunInvestigations(runId);
  const endpoints = useRunEndpoints(runId);
  const smartfuzz = useRunSmartfuzz(runId);

  const hostname = normalizeHostname(host.host || host.url);

  const counts = useMemo(() => {
    const matches = (url: string | undefined | null) =>
      hostnameFromURL(url) === hostname;
    return {
      findings: (findings.data ?? []).filter((f) => matches(f.url)).length,
      investigations: (investigations.data ?? []).filter((i) =>
        matches(i.found_at?.url),
      ).length,
      endpoints: (endpoints.data ?? []).filter((e) => matches(e.url)).length,
      smartfuzz: (smartfuzz.data ?? []).filter((s) => matches(s.host)).length,
    };
  }, [
    hostname,
    findings.data,
    investigations.data,
    endpoints.data,
    smartfuzz.data,
  ]);

  const tlsExpiry = host.tls?.not_after;
  const expiresInDays = tlsExpiry
    ? Math.round((new Date(tlsExpiry).getTime() - Date.now()) / 86_400_000)
    : null;

  return (
    <div className="grid gap-4 p-4 md:grid-cols-3">
      {/* Counts + actions */}
      <div className="md:col-span-3 flex flex-wrap items-center gap-2">
        <Stat label="findings" value={counts.findings} loading={findings.isLoading} />
        <Stat label="invest." value={counts.investigations} loading={investigations.isLoading} />
        <Stat label="endpoints" value={counts.endpoints} loading={endpoints.isLoading} />
        <Stat label="smartfuzz" value={counts.smartfuzz} loading={smartfuzz.isLoading} />
        <div className="ml-auto flex gap-2">
          <a
            href={host.url}
            target="_blank"
            rel="noopener noreferrer"
            className={cn(buttonVariants({ variant: "outline", size: "sm" }), "gap-1")}
          >
            Open <ExternalLink className="size-3.5" />
          </a>
          <Link
            href={`/runs/${encodeURIComponent(runId)}/hosts/${encodeURIComponent(hostname)}`}
            className={cn(buttonVariants({ size: "sm" }), "gap-1")}
          >
            View details <ArrowRight className="size-3.5" />
          </Link>
        </div>
      </div>

      {host.tech && host.tech.length > 0 && (
        <Section title="Tech stack">
          <div className="flex flex-wrap gap-1">
            {host.tech.map((t) => (
              <Badge key={t} variant="secondary" className="text-[11px]">
                {t}
              </Badge>
            ))}
          </div>
        </Section>
      )}

      {host.tls && (
        <Section title="TLS">
          <div className="space-y-1 text-xs">
            <Row icon={<Lock className="size-3" />} label="version">
              {host.tls.tls_version?.replace("tls", "TLS ") ?? "—"}
            </Row>
            {host.tls.cipher && <Row label="cipher">{host.tls.cipher}</Row>}
            {host.tls.subject_cn && <Row label="subject CN">{host.tls.subject_cn}</Row>}
            {host.tls.issuer_cn && <Row label="issuer">{host.tls.issuer_cn}</Row>}
            {tlsExpiry && (
              <Row label="expires">
                <span
                  className={
                    expiresInDays !== null && expiresInDays < 30
                      ? "text-amber-300"
                      : ""
                  }
                >
                  {new Date(tlsExpiry).toLocaleDateString()}
                  {expiresInDays !== null && ` (${expiresInDays} days)`}
                </span>
              </Row>
            )}
          </div>
        </Section>
      )}

      <Section title="Network">
        <div className="space-y-1 text-xs">
          <Row icon={<Server className="size-3" />} label="server">
            {host.webserver || <span className="text-muted-foreground">—</span>}
          </Row>
          <Row label="content-type">
            {host.content_type || <span className="text-muted-foreground">—</span>}
          </Row>
          <Row label="cdn">
            {host.cdn_name || <span className="text-muted-foreground">—</span>}
          </Row>
          {host.a && host.a.length > 0 && (
            <Row label="ips">
              <span className="font-mono text-[10px]">{host.a.join(", ")}</span>
            </Row>
          )}
          {host.cname && host.cname.length > 0 && (
            <Row label="cname">
              <span className="font-mono text-[10px]">{host.cname.join(" → ")}</span>
            </Row>
          )}
        </div>
      </Section>

      {host.tls?.subject_an && host.tls.subject_an.length > 0 && (
        <Section title={`Subject alt names (${host.tls.subject_an.length})`} className="md:col-span-3">
          <div className="flex flex-wrap gap-1">
            {host.tls.subject_an.map((s) => (
              <Badge
                key={s}
                variant="outline"
                className="font-mono text-[10px] font-normal"
              >
                {s}
              </Badge>
            ))}
          </div>
        </Section>
      )}

      <Section title="Manual review" className="md:col-span-3">
        <HostAnnotationEditor hostname={hostname} />
      </Section>
    </div>
  );
}

function Stat({
  label,
  value,
  loading,
}: {
  label: string;
  value: number;
  loading: boolean;
}) {
  return (
    <div className="rounded-md border bg-background px-3 py-1.5">
      <span className="font-medium tabular-nums mr-1.5">
        {loading ? "…" : value.toLocaleString()}
      </span>
      <span className="text-[10px] uppercase tracking-wider text-muted-foreground">
        {label}
      </span>
    </div>
  );
}

function Section({
  title,
  className,
  children,
}: {
  title: string;
  className?: string;
  children: React.ReactNode;
}) {
  return (
    <div className={cn("min-w-0", className)}>
      <div className="text-[11px] uppercase tracking-wider text-muted-foreground mb-2">
        {title}
      </div>
      {children}
    </div>
  );
}

function Row({
  icon,
  label,
  children,
}: {
  icon?: React.ReactNode;
  label: string;
  children: React.ReactNode;
}) {
  return (
    <div className="flex items-start gap-3 min-w-0">
      <span className="inline-flex items-center gap-1 w-24 text-muted-foreground shrink-0">
        {icon}
        {label}
      </span>
      <span className="flex-1 min-w-0 break-all">{children}</span>
    </div>
  );
}
