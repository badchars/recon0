"use client";

import Link from "next/link";
import { hostnameFromURL } from "@/lib/host";
import { cn } from "@/lib/utils";

// Wraps a URL or hostname in a router link to the matching Host Detail
// page within a run. If the input doesn't yield a sensible hostname
// (e.g. a relative path), renders plain text instead.
export function HostLink({
  url,
  runId,
  display,
  className,
}: {
  url: string;
  runId: string;
  /** Optional override of what to display (defaults to the input URL). */
  display?: string;
  className?: string;
}) {
  const hostname = hostnameFromURL(url);
  const text = display ?? url;

  if (!hostname || !runId) {
    return <span className={cn("font-mono", className)}>{text}</span>;
  }

  return (
    <Link
      href={`/runs/${encodeURIComponent(runId)}/hosts/${encodeURIComponent(hostname)}`}
      className={cn(
        "font-mono hover:text-sky-400 hover:underline underline-offset-2",
        className,
      )}
      onClick={(e) => e.stopPropagation()}
    >
      {text}
    </Link>
  );
}
