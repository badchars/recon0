"use client";

import { useEffect, useMemo, useRef, useState } from "react";
import { useLogs } from "@/lib/api/hooks";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { cn } from "@/lib/utils";

const LEVELS = ["all", "DEBUG", "INFO", "WARN", "ERROR", "METRIC"] as const;

function levelOf(line: string): string {
  const m = line.match(/\[(DEBUG|INFO|WARN|ERROR|METRIC)\]/);
  return m ? m[1] : "INFO";
}

function lineClass(level: string): string {
  switch (level) {
    case "ERROR":
      return "text-destructive";
    case "WARN":
      return "text-amber-300";
    case "METRIC":
      return "text-sky-300";
    case "DEBUG":
      return "text-muted-foreground/70";
    default:
      return "text-foreground/85";
  }
}

export function LogViewer({ runId }: { runId: string }) {
  const [lines, setLines] = useState(500);
  const [search, setSearch] = useState("");
  const [level, setLevel] = useState<(typeof LEVELS)[number]>("all");
  const [autoScroll, setAutoScroll] = useState(true);

  const { data, isLoading } = useLogs(runId, lines);
  const containerRef = useRef<HTMLDivElement>(null);

  const filtered = useMemo(() => {
    let rows = data?.lines ?? [];
    if (level !== "all") rows = rows.filter((l) => levelOf(l) === level);
    if (search) {
      const q = search.toLowerCase();
      rows = rows.filter((l) => l.toLowerCase().includes(q));
    }
    return rows;
  }, [data, level, search]);

  useEffect(() => {
    if (autoScroll && containerRef.current) {
      containerRef.current.scrollTop = containerRef.current.scrollHeight;
    }
  }, [filtered, autoScroll]);

  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-center gap-2">
        <Input
          placeholder="Filter…"
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          className="max-w-xs h-7 text-xs"
        />
        <Select value={level} onValueChange={(v) => setLevel(v as (typeof LEVELS)[number])}>
          <SelectTrigger className="w-[110px] h-7 text-xs">
            <SelectValue placeholder="Level" />
          </SelectTrigger>
          <SelectContent>
            {LEVELS.map((l) => (
              <SelectItem key={l} value={l}>
                {l === "all" ? "All levels" : l}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
        <Select
          value={String(lines)}
          onValueChange={(v) => v && setLines(parseInt(v))}
        >
          <SelectTrigger className="w-[110px] h-7 text-xs">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            {[100, 200, 500, 1000, 5000].map((n) => (
              <SelectItem key={n} value={String(n)}>
                last {n}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
        <Button
          variant={autoScroll ? "secondary" : "outline"}
          size="sm"
          onClick={() => setAutoScroll((s) => !s)}
        >
          {autoScroll ? "Auto-scroll: on" : "Auto-scroll: off"}
        </Button>
        <div className="ml-auto text-xs text-muted-foreground">
          {filtered.length} / {data?.lines?.length ?? 0} lines
        </div>
      </div>

      <div
        ref={containerRef}
        className="rounded-md border bg-muted/20 font-mono text-xs leading-relaxed h-[480px] overflow-auto p-3"
      >
        {isLoading ? (
          <div className="text-muted-foreground">Loading log…</div>
        ) : filtered.length === 0 ? (
          <div className="text-muted-foreground">No log lines match filter.</div>
        ) : (
          filtered.map((line, i) => (
            <div key={i} className={cn("whitespace-pre-wrap", lineClass(levelOf(line)))}>
              {line}
            </div>
          ))
        )}
      </div>
    </div>
  );
}
