"use client";

import Link from "next/link";
import { useMemo } from "react";
import { ArrowLeft, ExternalLink, Lock, Server } from "lucide-react";
import { buttonVariants } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import {
  Card,
  CardContent,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import {
  useRunEndpoints,
  useRunFindings,
  useRunHosts,
  useRunInvestigations,
  useRunSmartfuzz,
} from "@/lib/api/hooks";
import { hostnameFromURL, normalizeHostname } from "@/lib/host";
import { cn } from "@/lib/utils";
import { HostAnnotationEditor } from "@/components/runs/host-annotation-editor";
import { FindingsTab } from "@/components/runs/findings-tab";
import { InvestigationsTab } from "@/components/runs/investigations-tab";
import { EndpointsTab } from "@/components/runs/endpoints-tab";
import { SmartfuzzTab } from "@/components/runs/smartfuzz-tab";

export function HostDetailView({
  runId,
  hostname,
}: {
  runId: string;
  hostname: string;
}) {
  const hosts = useRunHosts(runId);
  const findings = useRunFindings(runId);
  const investigations = useRunInvestigations(runId);
  const endpoints = useRunEndpoints(runId);
  const smartfuzz = useRunSmartfuzz(runId);

  const canon = normalizeHostname(hostname);

  // Pick the matching host record (there can be multiple — different ports
  // or schemes — we take the first, prefer https).
  const host = useMemo(() => {
    const matches = (hosts.data ?? []).filter(
      (h) => normalizeHostname(h.host || h.url) === canon,
    );
    matches.sort((a, b) => {
      const aHttps = (a.scheme ?? a.url ?? "").includes("https") ? 0 : 1;
      const bHttps = (b.scheme ?? b.url ?? "").includes("https") ? 0 : 1;
      return aHttps - bHttps;
    });
    return matches[0];
  }, [hosts.data, canon]);

  const filteredFindings = useMemo(
    () => (findings.data ?? []).filter((f) => hostnameFromURL(f.url) === canon),
    [findings.data, canon],
  );
  const filteredInv = useMemo(
    () =>
      (investigations.data ?? []).filter(
        (i) => hostnameFromURL(i.found_at?.url) === canon,
      ),
    [investigations.data, canon],
  );
  const filteredEndpoints = useMemo(
    () => (endpoints.data ?? []).filter((e) => hostnameFromURL(e.url) === canon),
    [endpoints.data, canon],
  );
  const filteredSmartfuzz = useMemo(
    () => (smartfuzz.data ?? []).filter((s) => hostnameFromURL(s.host) === canon),
    [smartfuzz.data, canon],
  );

  if (hosts.isLoading) {
    return <div className="p-6 text-sm text-muted-foreground">Loading host…</div>;
  }

  if (!host) {
    return (
      <div className="p-6 space-y-4">
        <Link
          href={`/runs/${encodeURIComponent(runId)}`}
          className={cn(buttonVariants({ variant: "ghost", size: "sm" }), "gap-1 -ml-2")}
        >
          <ArrowLeft className="size-3.5" /> Back to run
        </Link>
        <Card>
          <CardContent className="py-12 text-center">
            <p className="text-sm">Host not found in this run.</p>
            <p className="text-xs text-muted-foreground mt-1 font-mono">
              {canon}
            </p>
          </CardContent>
        </Card>
      </div>
    );
  }

  const tlsExpiry = host.tls?.not_after;
  const expiresInDays = tlsExpiry
    ? Math.round((new Date(tlsExpiry).getTime() - Date.now()) / 86_400_000)
    : null;

  return (
    <div className="p-6 space-y-6">
      <div>
        <Link
          href={`/runs/${encodeURIComponent(runId)}`}
          className={cn(buttonVariants({ variant: "ghost", size: "sm" }), "gap-1 -ml-2")}
        >
          <ArrowLeft className="size-3.5" /> Run
        </Link>
      </div>

      <div className="space-y-1">
        <div className="flex items-center gap-3 flex-wrap">
          <h1 className="text-2xl font-semibold tracking-tight font-mono break-all">
            {canon}
          </h1>
          <Badge variant="outline" className="tabular-nums">
            {host.status_code ?? "—"}
          </Badge>
          <a
            href={host.url}
            target="_blank"
            rel="noopener noreferrer"
            className={cn(buttonVariants({ variant: "outline", size: "sm" }), "gap-1 ml-auto")}
          >
            Open <ExternalLink className="size-3.5" />
          </a>
        </div>
        {host.title && (
          <div className="text-sm text-muted-foreground">{host.title}</div>
        )}
        <div className="text-xs text-muted-foreground font-mono">{host.url}</div>
      </div>

      <Card>
        <CardHeader>
          <CardTitle className="text-sm">Manual review</CardTitle>
        </CardHeader>
        <CardContent>
          <HostAnnotationEditor hostname={canon} />
        </CardContent>
      </Card>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <Card>
          <CardHeader>
            <CardTitle className="text-sm">Tech & Server</CardTitle>
          </CardHeader>
          <CardContent className="space-y-3 text-xs">
            <div className="flex flex-wrap gap-1">
              {(host.tech ?? []).map((t) => (
                <Badge key={t} variant="secondary" className="text-[11px]">
                  {t}
                </Badge>
              ))}
              {(!host.tech || host.tech.length === 0) && (
                <span className="text-muted-foreground">No tech detected</span>
              )}
            </div>
            <Row icon={<Server className="size-3" />} label="webserver">
              {host.webserver || <span className="text-muted-foreground">—</span>}
            </Row>
            <Row label="content-type">
              {host.content_type || <span className="text-muted-foreground">—</span>}
            </Row>
            <Row label="content-length">
              {host.content_length?.toLocaleString() ?? (
                <span className="text-muted-foreground">—</span>
              )}
            </Row>
            <Row label="http2">{host.http2 ? "yes" : "no"}</Row>
            <Row label="cdn">
              {host.cdn_name || <span className="text-muted-foreground">—</span>}
            </Row>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle className="text-sm flex items-center gap-1">
              <Lock className="size-3.5" /> TLS
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-2 text-xs">
            {host.tls ? (
              <>
                <Row label="version">
                  {host.tls.tls_version?.replace("tls", "TLS ") ?? "—"}
                </Row>
                <Row label="cipher">{host.tls.cipher ?? "—"}</Row>
                <Row label="subject CN">{host.tls.subject_cn ?? "—"}</Row>
                <Row label="issuer">{host.tls.issuer_cn ?? "—"}</Row>
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
                {host.tls.subject_an && host.tls.subject_an.length > 0 && (
                  <Row label={`SAN (${host.tls.subject_an.length})`}>
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
                  </Row>
                )}
              </>
            ) : (
              <span className="text-muted-foreground">No TLS data</span>
            )}
          </CardContent>
        </Card>

        <Card className="md:col-span-2">
          <CardHeader>
            <CardTitle className="text-sm">Network</CardTitle>
          </CardHeader>
          <CardContent className="space-y-2 text-xs">
            {host.a && host.a.length > 0 && (
              <Row label="ip addresses">
                <span className="font-mono text-[11px]">{host.a.join(", ")}</span>
              </Row>
            )}
            {host.cname && host.cname.length > 0 && (
              <Row label="cname chain">
                <span className="font-mono text-[11px]">{host.cname.join(" → ")}</span>
              </Row>
            )}
            <Row label="port">{host.port ?? "—"}</Row>
            <Row label="scheme">{host.scheme ?? "—"}</Row>
          </CardContent>
        </Card>
      </div>

      <Tabs defaultValue="findings">
        <TabsList>
          <TabsTrigger value="findings">
            Findings <CountBadge n={filteredFindings.length} />
          </TabsTrigger>
          <TabsTrigger value="investigations">
            Investigations <CountBadge n={filteredInv.length} />
          </TabsTrigger>
          <TabsTrigger value="endpoints">
            Endpoints <CountBadge n={filteredEndpoints.length} />
          </TabsTrigger>
          <TabsTrigger value="smartfuzz">
            Smartfuzz <CountBadge n={filteredSmartfuzz.length} />
          </TabsTrigger>
        </TabsList>

        <TabsContent value="findings" className="pt-4">
          <FindingsTab runId={runId} hostFilter={canon} />
        </TabsContent>
        <TabsContent value="investigations" className="pt-4">
          <InvestigationsTab runId={runId} hostFilter={canon} />
        </TabsContent>
        <TabsContent value="endpoints" className="pt-4">
          <EndpointsTab runId={runId} hostFilter={canon} />
        </TabsContent>
        <TabsContent value="smartfuzz" className="pt-4">
          <SmartfuzzTab runId={runId} hostFilter={canon} />
        </TabsContent>
      </Tabs>
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
      <span className="inline-flex items-center gap-1 w-32 text-muted-foreground shrink-0">
        {icon}
        {label}
      </span>
      <span className="flex-1 min-w-0 break-all">{children}</span>
    </div>
  );
}

function CountBadge({ n }: { n: number }) {
  if (n === 0) return null;
  return (
    <Badge variant="secondary" className="ml-1.5 text-[10px] tabular-nums">
      {n}
    </Badge>
  );
}

