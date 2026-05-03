"use client";

import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import {
  Field,
  FieldGroup,
  FieldLabel,
  FieldDescription,
} from "@/components/ui/field";
import { useVulnerabilities } from "@/lib/api/hooks";
import { getBaseUrl } from "@/lib/api/recon0";

export default function SettingsPage() {
  const instanceUrl = getBaseUrl();

  const { data: vulns } = useVulnerabilities();
  const vulnCount = vulns?.length ?? 0;

  function exportVulns() {
    const data = JSON.stringify(vulns ?? [], null, 2);
    const blob = new Blob([data], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `recon0-vulns-${new Date().toISOString().slice(0, 10)}.json`;
    a.click();
    URL.revokeObjectURL(url);
  }

  return (
    <div className="p-6 space-y-6 max-w-3xl">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight">Settings</h1>
        <p className="text-sm text-muted-foreground">
          Panel ve recon0 instance konfigürasyonu.
        </p>
      </div>

      <Card>
        <CardHeader>
          <CardTitle className="text-base">recon0 instance</CardTitle>
        </CardHeader>
        <CardContent>
          <FieldGroup>
            <Field>
              <FieldLabel htmlFor="instanceUrl">URL</FieldLabel>
              <Input
                id="instanceUrl"
                value={instanceUrl}
                readOnly
                className="font-mono opacity-70 cursor-not-allowed"
              />
              <FieldDescription>
                <code className="font-mono">.env.local</code> dosyasındaki{" "}
                <code className="font-mono">NEXT_PUBLIC_RECON0_URL</code>&apos;den
                okunur. Değiştirmek için dosyayı düzenleyip{" "}
                <code className="font-mono">npm run dev</code>&apos;i yeniden
                başlatın.
              </FieldDescription>
            </Field>
          </FieldGroup>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="text-base">Local data (panel)</CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="flex items-center justify-between text-sm">
            <span className="text-muted-foreground">Vulnerabilities</span>
            <span className="tabular-nums">{vulnCount}</span>
          </div>
          <div className="flex flex-wrap gap-2">
            <Button variant="outline" size="sm" onClick={exportVulns}>
              Export as JSON
            </Button>
          </div>
          <p className="text-xs text-muted-foreground">
            Vulnerabilities recon0 daemon&apos;da
            <code className="font-mono"> runs/vulnerabilities.json</code>
            &apos;da saklanır. Bu dosyayı yedekle ya da rsync ile başka makineye
            taşı.
          </p>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="text-base">About</CardTitle>
        </CardHeader>
        <CardContent className="text-sm text-muted-foreground space-y-1">
          <div>recon0 panel v0.1.0</div>
          <div>Built with Next.js, shadcn/ui, TanStack Query, Zustand</div>
        </CardContent>
      </Card>
    </div>
  );
}
