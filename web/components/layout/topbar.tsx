"use client";

import { useHealth } from "@/lib/api/hooks";
import { getBaseUrl } from "@/lib/api/recon0";
import { Button } from "@/components/ui/button";
import { Plus, Wifi, WifiOff } from "lucide-react";
import { useState } from "react";
import { CreateRunModal } from "@/components/create-run-modal";

export function Topbar() {
  const { data, isError } = useHealth();
  const instanceUrl = getBaseUrl();
  const [open, setOpen] = useState(false);

  const healthy = !!data?.ok && !isError;

  return (
    <>
      <header className="h-14 border-b bg-background/80 backdrop-blur flex items-center px-4 gap-3">
        <div className="flex items-center gap-2 text-xs text-muted-foreground">
          {healthy ? (
            <>
              <Wifi className="size-4 text-emerald-500" />
              <span className="hidden md:inline">{instanceUrl}</span>
            </>
          ) : (
            <>
              <WifiOff className="size-4 text-destructive" />
              <span className="text-destructive">API offline · {instanceUrl}</span>
            </>
          )}
        </div>
        <div className="ml-auto flex items-center gap-2">
          <Button size="sm" onClick={() => setOpen(true)} className="gap-1.5">
            <Plus className="size-4" />
            Create Run
          </Button>
        </div>
      </header>
      <CreateRunModal open={open} onOpenChange={setOpen} />
    </>
  );
}
