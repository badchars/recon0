"use client";

import { useRouter } from "next/navigation";
import { toast } from "sonner";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { useDeleteProgram, useRuns, useVulnerabilities } from "@/lib/api/hooks";

export function ProgramDeleteDialog({
  programName,
  open,
  onOpenChange,
}: {
  programName: string;
  open: boolean;
  onOpenChange: (v: boolean) => void;
}) {
  const router = useRouter();
  const remove = useDeleteProgram();
  const { data: runs } = useRuns();
  const { data: vulns } = useVulnerabilities();

  const runCount = (runs ?? []).filter((r) => r.program === programName).length;
  const vulnCount = (vulns ?? []).filter((v) => v.program === programName)
    .length;

  async function onDelete() {
    try {
      await remove.mutateAsync(programName);
      toast.success("Program deleted");
      router.push("/programs");
    } catch (err) {
      toast.error("Delete failed", { description: String(err) });
    }
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Delete {programName}?</DialogTitle>
          <DialogDescription>
            {runCount > 0 || vulnCount > 0 ? (
              <>
                This program is referenced by{" "}
                <strong>{runCount} run{runCount === 1 ? "" : "s"}</strong> and{" "}
                <strong>
                  {vulnCount} vulnerabilit{vulnCount === 1 ? "y" : "ies"}
                </strong>
                . They&apos;ll continue to exist but will no longer link to a
                registered program.
              </>
            ) : (
              "This action cannot be undone."
            )}
          </DialogDescription>
        </DialogHeader>
        <DialogFooter>
          <Button variant="ghost" onClick={() => onOpenChange(false)}>
            Cancel
          </Button>
          <Button
            variant="destructive"
            onClick={onDelete}
            disabled={remove.isPending}
          >
            {remove.isPending ? "Deleting…" : "Delete"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
