"use client";

import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { X } from "lucide-react";
import { useQueue, useRemoveQueued } from "@/lib/api/hooks";
import { formatRelative } from "@/lib/format";
import { toast } from "sonner";

export function PendingQueue() {
  const { data, isLoading } = useQueue();
  const remove = useRemoveQueued();

  const pending = (data?.jobs ?? []).filter((j) => j.status === "queued");

  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-sm flex items-center justify-between">
          <span>Pending queue</span>
          <span className="text-muted-foreground font-normal">
            {pending.length}
          </span>
        </CardTitle>
      </CardHeader>
      <CardContent>
        {isLoading ? (
          <div className="text-xs text-muted-foreground">Loading…</div>
        ) : pending.length === 0 ? (
          <div className="text-xs text-muted-foreground">
            No pending jobs.
          </div>
        ) : (
          <ul className="space-y-2">
            {pending.map((job) => (
              <li
                key={job.id}
                className="flex items-center gap-2 text-sm border rounded-md px-3 py-2"
              >
                <div className="flex-1 min-w-0">
                  <div className="truncate font-mono text-xs">
                    {job.domain}
                  </div>
                  <div className="text-xs text-muted-foreground">
                    {job.program} · queued {formatRelative(job.created_at)}
                  </div>
                </div>
                <Button
                  variant="ghost"
                  size="icon"
                  className="size-7"
                  onClick={async () => {
                    try {
                      await remove.mutateAsync(job.id);
                      toast.success(`Removed ${job.id}`);
                    } catch {
                      toast.error("Could not remove job");
                    }
                  }}
                  aria-label="Remove from queue"
                >
                  <X className="size-3.5" />
                </Button>
              </li>
            ))}
          </ul>
        )}
      </CardContent>
    </Card>
  );
}
