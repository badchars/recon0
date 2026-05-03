"use client";

import Link from "next/link";
import { useMemo, useState } from "react";
import {
  ArrowLeft,
  ExternalLink,
  Pencil,
  Plus,
  Trash2,
} from "lucide-react";
import { Button, buttonVariants } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent } from "@/components/ui/card";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import {
  useProgram,
  useRuns,
  useVulnerabilities,
} from "@/lib/api/hooks";
import { RunsTable } from "@/components/runs/runs-table";
import { VulnsTable } from "@/components/vulnerabilities/vulns-table";
import { ProgramAssetsTab } from "@/components/programs/program-assets-tab";
import { ProgramEditDialog } from "@/components/programs/program-edit-dialog";
import { ProgramDeleteDialog } from "@/components/programs/program-delete-dialog";
import { CreateRunModal } from "@/components/create-run-modal";
import { cn } from "@/lib/utils";

const VENDOR_VARIANT: Record<string, string> = {
  hackerone: "border-border text-muted-foreground",
  bugcrowd: "border-amber-500/40 text-amber-300",
  yeswehack: "border-emerald-500/40 text-emerald-400",
  intigriti: "border-sky-500/40 text-sky-400",
  private: "border-border text-muted-foreground",
};

export function ProgramDashboard({ name }: { name: string }) {
  const program = useProgram(name);
  const { data: runs } = useRuns();
  const { data: vulns } = useVulnerabilities();

  const [editOpen, setEditOpen] = useState(false);
  const [deleteOpen, setDeleteOpen] = useState(false);
  const [createRunOpen, setCreateRunOpen] = useState(false);

  const runCount = useMemo(
    () => (runs ?? []).filter((r) => r.program === name).length,
    [runs, name],
  );
  const programVulns = useMemo(
    () => (vulns ?? []).filter((v) => v.program === name),
    [vulns, name],
  );
  const totalBounty = programVulns.reduce(
    (sum, v) => sum + (v.bounty ?? 0),
    0,
  );

  if (program.isLoading) {
    return (
      <div className="p-6 text-sm text-muted-foreground">Loading program…</div>
    );
  }
  if (program.isError || !program.data) {
    return (
      <div className="p-6 space-y-4">
        <Link
          href="/programs"
          className={cn(buttonVariants({ variant: "ghost", size: "sm" }), "gap-1 -ml-2")}
        >
          <ArrowLeft className="size-3.5" /> Programs
        </Link>
        <p className="text-sm text-destructive">Program not found.</p>
      </div>
    );
  }

  const p = program.data;

  return (
    <div className="p-6 space-y-6">
      <div className="flex items-center gap-2">
        <Link
          href="/programs"
          className={cn(buttonVariants({ variant: "ghost", size: "sm" }), "gap-1 -ml-2")}
        >
          <ArrowLeft className="size-3.5" /> Programs
        </Link>
      </div>

      {/* Header */}
      <div className="space-y-3">
        <div className="flex items-start gap-3 flex-wrap">
          <div className="flex-1 min-w-0">
            <div className="flex items-center gap-2 flex-wrap">
              <h1 className="text-2xl font-semibold tracking-tight font-mono">
                {p.name}
              </h1>
              {p.vendor && (
                <Badge
                  variant="outline"
                  className={cn(
                    "text-[10px]",
                    VENDOR_VARIANT[p.vendor.toLowerCase()] ??
                      "border-border text-muted-foreground",
                  )}
                >
                  {p.vendor}
                </Badge>
              )}
              {p.vendor_link && (
                <a
                  href={p.vendor_link}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="text-muted-foreground hover:text-sky-400 inline-flex items-center gap-0.5 text-xs"
                >
                  open <ExternalLink className="size-3" />
                </a>
              )}
            </div>
            {p.description && (
              <p className="text-sm text-muted-foreground mt-1">
                {p.description}
              </p>
            )}
          </div>
          <div className="flex items-center gap-2 shrink-0">
            <Button size="sm" onClick={() => setCreateRunOpen(true)} className="gap-1">
              <Plus className="size-3.5" /> Run scan
            </Button>
            <Button
              size="sm"
              variant="outline"
              onClick={() => setEditOpen(true)}
              className="gap-1"
            >
              <Pencil className="size-3.5" /> Edit
            </Button>
            <Button
              size="sm"
              variant="destructive"
              onClick={() => setDeleteOpen(true)}
              className="gap-1"
            >
              <Trash2 className="size-3.5" /> Delete
            </Button>
          </div>
        </div>

        {/* Stats line */}
        <div className="flex items-center gap-4 text-xs text-muted-foreground">
          <span>
            <strong className="text-foreground">{runCount}</strong> run{runCount === 1 ? "" : "s"}
          </span>
          <span>·</span>
          <span>
            <strong className="text-foreground">{programVulns.length}</strong>{" "}
            vuln{programVulns.length === 1 ? "" : "s"}
          </span>
          {totalBounty > 0 && (
            <>
              <span>·</span>
              <span className="text-emerald-400">
                ${totalBounty.toLocaleString()} earned
              </span>
            </>
          )}
        </div>

        {/* Scope chips */}
        {p.scope.length > 0 && (
          <Card className="bg-muted/20">
            <CardContent className="py-3">
              <div className="text-[11px] uppercase tracking-wider text-muted-foreground mb-2">
                Scope
              </div>
              <div className="flex flex-wrap gap-1">
                {p.scope.map((s) => (
                  <Badge
                    key={s}
                    variant="outline"
                    className="font-mono text-[11px] font-normal"
                  >
                    {s}
                  </Badge>
                ))}
              </div>
            </CardContent>
          </Card>
        )}
      </div>

      {/* Tabs */}
      <Tabs defaultValue="runs">
        <TabsList>
          <TabsTrigger value="runs">
            Runs
            {runCount > 0 && (
              <Badge variant="secondary" className="ml-1.5 text-[10px] tabular-nums">
                {runCount}
              </Badge>
            )}
          </TabsTrigger>
          <TabsTrigger value="vulns">
            Vulnerabilities
            {programVulns.length > 0 && (
              <Badge variant="secondary" className="ml-1.5 text-[10px] tabular-nums">
                {programVulns.length}
              </Badge>
            )}
          </TabsTrigger>
          <TabsTrigger value="assets">Assets</TabsTrigger>
        </TabsList>
        <TabsContent value="runs" className="pt-4">
          <RunsTable programFilter={name} />
        </TabsContent>
        <TabsContent value="vulns" className="pt-4">
          <VulnsTable programFilter={name} />
        </TabsContent>
        <TabsContent value="assets" className="pt-4">
          <ProgramAssetsTab programName={name} />
        </TabsContent>
      </Tabs>

      <ProgramEditDialog program={p} open={editOpen} onOpenChange={setEditOpen} />
      <ProgramDeleteDialog
        programName={name}
        open={deleteOpen}
        onOpenChange={setDeleteOpen}
      />
      <CreateRunModal
        open={createRunOpen}
        onOpenChange={setCreateRunOpen}
        defaultProgram={name}
      />
    </div>
  );
}
