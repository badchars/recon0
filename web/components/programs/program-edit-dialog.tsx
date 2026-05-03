"use client";

import { useEffect, useState } from "react";
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
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import {
  Field,
  FieldGroup,
  FieldLabel,
  FieldDescription,
} from "@/components/ui/field";
import { useUpdateProgram } from "@/lib/api/hooks";
import type { Program } from "@/lib/api/types";

const VENDOR_SUGGESTIONS = [
  "hackerone",
  "bugcrowd",
  "yeswehack",
  "intigriti",
  "private",
];

// Edit-only dialog — name is immutable so it's not in the form.
// Used by Program dashboard. Create flow stays at /programs/new.
export function ProgramEditDialog({
  program,
  open,
  onOpenChange,
}: {
  program: Program;
  open: boolean;
  onOpenChange: (v: boolean) => void;
}) {
  const update = useUpdateProgram();

  const [description, setDescription] = useState(program.description);
  const [vendor, setVendor] = useState(program.vendor);
  const [vendorLink, setVendorLink] = useState(program.vendor_link);
  const [scopeText, setScopeText] = useState(program.scope.join("\n"));

  // Reset local state when the dialog opens fresh — picks up server changes
  useEffect(() => {
    if (open) {
      setDescription(program.description);
      setVendor(program.vendor);
      setVendorLink(program.vendor_link);
      setScopeText(program.scope.join("\n"));
    }
  }, [open, program]);

  async function onSave() {
    const scope = Array.from(
      new Set(
        scopeText
          .split(/[\n,]/)
          .map((s) => s.trim())
          .filter(Boolean),
      ),
    );
    try {
      await update.mutateAsync({
        name: program.name,
        description: description.trim(),
        vendor: vendor.trim(),
        vendor_link: vendorLink.trim(),
        scope,
        expected_version: program.version,
      });
      toast.success("Program updated");
      onOpenChange(false);
    } catch (err) {
      toast.error("Save failed", { description: String(err) });
    }
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-2xl">
        <DialogHeader>
          <DialogTitle>Edit {program.name}</DialogTitle>
          <DialogDescription>
            Name is immutable. Update vendor, link, or scope as needed.
          </DialogDescription>
        </DialogHeader>

        <FieldGroup>
          <Field>
            <FieldLabel>Description</FieldLabel>
            <Textarea
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              className="min-h-[70px]"
            />
          </Field>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <Field>
              <FieldLabel>Vendor</FieldLabel>
              <Input
                list="program-edit-vendors"
                value={vendor}
                onChange={(e) => setVendor(e.target.value)}
                autoComplete="off"
              />
              <datalist id="program-edit-vendors">
                {VENDOR_SUGGESTIONS.map((v) => (
                  <option key={v} value={v} />
                ))}
              </datalist>
            </Field>
            <Field>
              <FieldLabel>Vendor link</FieldLabel>
              <Input
                value={vendorLink}
                onChange={(e) => setVendorLink(e.target.value)}
              />
            </Field>
          </div>

          <Field>
            <FieldLabel>Scope</FieldLabel>
            <Textarea
              value={scopeText}
              onChange={(e) => setScopeText(e.target.value)}
              placeholder={"*.income.com.sg\napi.income.com.sg"}
              className="min-h-[120px] font-mono text-sm"
            />
            <FieldDescription>One asset per line.</FieldDescription>
          </Field>
        </FieldGroup>

        <DialogFooter>
          <Button variant="ghost" onClick={() => onOpenChange(false)}>
            Cancel
          </Button>
          <Button onClick={onSave} disabled={update.isPending}>
            {update.isPending ? "Saving…" : "Save"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
