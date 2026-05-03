"use client";

import { useState } from "react";
import { CheckCircle2, XCircle } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import {
  Field,
  FieldGroup,
  FieldLabel,
  FieldDescription,
} from "@/components/ui/field";
import { useSettings } from "@/lib/store/settings";
import { useVulnerabilities } from "@/lib/api/hooks";
import { recon0, setBaseUrl } from "@/lib/api/recon0";
import { toast } from "sonner";

export default function SettingsPage() {
  const instanceUrl = useSettings((s) => s.instanceUrl);
  const setInstanceUrl = useSettings((s) => s.setInstanceUrl);
  const [draft, setDraft] = useState(instanceUrl);
  const [testing, setTesting] = useState(false);
  const [testResult, setTestResult] = useState<"ok" | "fail" | null>(null);

  const { data: vulns } = useVulnerabilities();
  const vulnCount = vulns?.length ?? 0;

  async function testConnection() {
    setTesting(true);
    setTestResult(null);
    setBaseUrl(draft);
    try {
      const r = await recon0.health();
      setTestResult(r.ok ? "ok" : "fail");
    } catch {
      setTestResult("fail");
    } finally {
      setTesting(false);
      // restore current URL — applying happens on Save
      setBaseUrl(instanceUrl);
    }
  }

  function save() {
    const trimmed = draft.replace(/\/+$/, "");
    setInstanceUrl(trimmed);
    toast.success("Settings saved");
  }

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
              <div className="flex gap-2">
                <Input
                  id="instanceUrl"
                  value={draft}
                  onChange={(e) => setDraft(e.target.value)}
                  placeholder="http://localhost:8484"
                  className="font-mono"
                />
                <Button
                  variant="outline"
                  onClick={testConnection}
                  disabled={testing}
                >
                  {testing ? "Testing…" : "Test"}
                </Button>
                <Button onClick={save} disabled={draft === instanceUrl}>
                  Save
                </Button>
              </div>
              <FieldDescription>
                recon0 daemon&apos;ın API adresi (default: 8484 portu).
              </FieldDescription>
              {testResult === "ok" && (
                <div className="flex items-center gap-1.5 text-xs text-emerald-400">
                  <CheckCircle2 className="size-3.5" /> Connection OK
                </div>
              )}
              {testResult === "fail" && (
                <div className="flex items-center gap-1.5 text-xs text-destructive">
                  <XCircle className="size-3.5" /> Connection failed
                </div>
              )}
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
