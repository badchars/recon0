"use client";

import Link from "next/link";
import { useMemo, useState } from "react";
import { Briefcase, ExternalLink, Plus } from "lucide-react";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { buttonVariants } from "@/components/ui/button";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { usePrograms } from "@/lib/api/hooks";
import { formatRelative } from "@/lib/format";
import { cn } from "@/lib/utils";

const VENDOR_VARIANT: Record<string, string> = {
  hackerone: "border-border text-muted-foreground",
  bugcrowd: "border-amber-500/40 text-amber-300",
  yeswehack: "border-emerald-500/40 text-emerald-400",
  intigriti: "border-sky-500/40 text-sky-400",
  private: "border-border text-muted-foreground",
};

export function ProgramsTable() {
  const { data, isLoading, isError } = usePrograms();
  const [search, setSearch] = useState("");

  const filtered = useMemo(() => {
    const list = data ?? [];
    const q = search.trim().toLowerCase();
    if (!q) return list;
    return list.filter(
      (p) =>
        p.name.toLowerCase().includes(q) ||
        p.description.toLowerCase().includes(q) ||
        p.vendor.toLowerCase().includes(q),
    );
  }, [data, search]);

  if (isError) {
    return (
      <div className="text-sm text-destructive p-6">
        Failed to load programs.
      </div>
    );
  }

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center gap-2">
        <Input
          placeholder="Search name, description, vendor…"
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          className="max-w-xs"
        />
        <div className="ml-auto flex items-center gap-2">
          <span className="text-xs text-muted-foreground">
            {filtered.length} of {data?.length ?? 0}
          </span>
          <Link
            href="/programs/new"
            className={cn(buttonVariants({ size: "sm" }), "gap-1")}
          >
            <Plus className="size-3.5" /> New Program
          </Link>
        </div>
      </div>

      <div className="rounded-md border overflow-x-auto">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead className="w-[200px]">Name</TableHead>
              <TableHead className="w-[120px]">Vendor</TableHead>
              <TableHead>Description</TableHead>
              <TableHead className="w-[80px] text-right">Scope</TableHead>
              <TableHead className="w-[140px] text-right">Updated</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {isLoading ? (
              <TableRow>
                <TableCell colSpan={5} className="text-center py-8 text-muted-foreground">
                  Loading…
                </TableCell>
              </TableRow>
            ) : filtered.length === 0 ? (
              <TableRow>
                <TableCell colSpan={5} className="text-center py-12">
                  <Briefcase className="size-8 mx-auto text-muted-foreground/50 mb-2" />
                  <p className="text-sm text-muted-foreground">
                    {(data?.length ?? 0) === 0
                      ? "No programs yet."
                      : "No programs match the search."}
                  </p>
                  {(data?.length ?? 0) === 0 && (
                    <Link
                      href="/programs/new"
                      className={cn(
                        buttonVariants({ variant: "outline", size: "sm" }),
                        "mt-3 gap-1",
                      )}
                    >
                      <Plus className="size-3.5" /> Create your first
                    </Link>
                  )}
                </TableCell>
              </TableRow>
            ) : (
              filtered.map((p) => (
                <TableRow key={p.name} className="hover:bg-muted/50">
                  <TableCell>
                    <Link
                      href={`/programs/${encodeURIComponent(p.name)}`}
                      className="font-medium hover:underline"
                    >
                      {p.name}
                    </Link>
                  </TableCell>
                  <TableCell>
                    {p.vendor ? (
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
                    ) : (
                      <span className="text-xs text-muted-foreground">—</span>
                    )}
                    {p.vendor_link && (
                      <a
                        href={p.vendor_link}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="ml-1.5 text-muted-foreground hover:text-sky-400"
                        onClick={(e) => e.stopPropagation()}
                      >
                        <ExternalLink className="inline size-3" />
                      </a>
                    )}
                  </TableCell>
                  <TableCell className="text-xs">
                    <div className="truncate max-w-2xl text-muted-foreground">
                      {p.description || (
                        <span className="italic">no description</span>
                      )}
                    </div>
                  </TableCell>
                  <TableCell className="text-right tabular-nums text-xs text-muted-foreground">
                    {p.scope.length}
                  </TableCell>
                  <TableCell className="text-right tabular-nums text-xs text-muted-foreground">
                    {formatRelative(p.updated_at)}
                  </TableCell>
                </TableRow>
              ))
            )}
          </TableBody>
        </Table>
      </div>
    </div>
  );
}
