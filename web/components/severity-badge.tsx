import { cn } from "@/lib/utils";
import type { Severity } from "@/lib/api/types";

const COLOR: Record<Severity, string> = {
  critical: "bg-sev-critical-soft text-sev-critical border-sev-critical/40",
  high: "bg-sev-high-soft text-sev-high border-sev-high/40",
  medium: "bg-sev-medium-soft text-sev-medium border-sev-medium/40",
  low: "bg-sev-low-soft text-sev-low border-sev-low/40",
  info: "bg-sev-info-soft text-sev-info border-sev-info/40",
};

// Accepts string so callers using non-strict-typed data (e.g. raw JSONL
// records) can still render. Unknown severities fall through to "info".
export function SeverityBadge({
  severity,
  className,
}: {
  severity: Severity | string;
  className?: string;
}) {
  const key = (severity as Severity) in COLOR ? (severity as Severity) : "info";
  return (
    <span
      className={cn(
        "inline-flex items-center rounded border px-1.5 py-0.5 text-[10px] uppercase font-medium tracking-wider",
        COLOR[key],
        className,
      )}
    >
      {severity}
    </span>
  );
}
