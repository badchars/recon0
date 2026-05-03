"use client";

import { useEffect } from "react";
import { toast } from "sonner";
import { recon0 } from "@/lib/api/recon0";
import type { CreateVulnBody, Severity, SubmissionStatus } from "@/lib/api/types";

const STORAGE_KEY = "recon0-panel-vulns";

// Old shape (Zustand persist):
//   { vulns: [{ id, title, severity, status, asset, program?, description,
//               poc, references, tags, ... }] }
//
// We map to new server schema:
//   - description ← description + (poc ? "\n\n## Proof of Concept\n\n" + poc : "")
//   - submission_status ← "wait" (the old `status` enum doesn't translate cleanly)
//   - bounty ← 0
type LegacyVuln = {
  title?: string;
  severity?: string;
  status?: string;
  asset?: string;
  program?: string;
  description?: string;
  poc?: string;
  references?: string[];
  tags?: string[];
  source_run_id?: string;
  source_finding_id?: string;
};

function isSeverity(s: string | undefined): s is Severity {
  return s === "critical" || s === "high" || s === "medium" || s === "low" || s === "info";
}

function toCreateBody(v: LegacyVuln): CreateVulnBody | null {
  if (!v?.title?.trim() || !v?.asset?.trim()) return null;
  const sev: Severity = isSeverity(v.severity) ? v.severity : "medium";
  const status: SubmissionStatus = "wait";

  const desc = v.description ?? "";
  const poc = v.poc?.trim();
  const fullDesc = poc ? `${desc}\n\n## Proof of Concept\n\n${poc}`.trim() : desc;

  return {
    title: v.title.trim(),
    severity: sev,
    submission_status: status,
    bounty: 0,
    asset: v.asset.trim(),
    program: v.program?.trim() || undefined,
    description: fullDesc,
    references: Array.isArray(v.references) ? v.references : [],
    tags: Array.isArray(v.tags) ? v.tags : [],
    source_run_id: v.source_run_id,
    source_finding_id: v.source_finding_id,
  };
}

// Run once on app mount: if legacy localStorage vulns exist, push them to
// the server one by one. Successful migration clears localStorage so we
// don't double-post on next load.
export function VulnMigration() {
  useEffect(() => {
    const raw = typeof window !== "undefined" ? localStorage.getItem(STORAGE_KEY) : null;
    if (!raw) return;

    let parsed: { state?: { vulns?: LegacyVuln[] } } | null = null;
    try {
      parsed = JSON.parse(raw);
    } catch {
      // Corrupt — drop it silently.
      localStorage.removeItem(STORAGE_KEY);
      return;
    }
    const legacy = parsed?.state?.vulns ?? [];
    if (!Array.isArray(legacy) || legacy.length === 0) {
      localStorage.removeItem(STORAGE_KEY);
      return;
    }

    let cancelled = false;
    (async () => {
      const t = toast.loading(
        `Migrating ${legacy.length} vulnerability${legacy.length > 1 ? "ies" : ""} to server…`,
      );
      let ok = 0;
      let fail = 0;
      for (const v of legacy) {
        if (cancelled) return;
        const body = toCreateBody(v);
        if (!body) {
          fail++;
          continue;
        }
        try {
          await recon0.createVuln(body);
          ok++;
        } catch {
          fail++;
        }
      }
      if (cancelled) return;
      if (ok > 0 && fail === 0) {
        localStorage.removeItem(STORAGE_KEY);
        toast.success(`Migrated ${ok} vulnerabilities to server`, { id: t });
      } else if (ok > 0) {
        toast.warning(
          `Migrated ${ok} of ${legacy.length} — ${fail} failed. localStorage kept for retry.`,
          { id: t },
        );
      } else {
        toast.error(`Migration failed (${fail} errors). localStorage kept.`, { id: t });
      }
    })();

    return () => {
      cancelled = true;
    };
  }, []);

  return null;
}
