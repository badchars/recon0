"use client";

import { useState } from "react";
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
  FieldError,
} from "@/components/ui/field";
import { useCreateProgram } from "@/lib/api/hooks";
import type { Program } from "@/lib/api/types";

const SLUG_RE = /^[a-z0-9][a-z0-9-]{0,62}$/;
const VENDOR_SUGGESTIONS = [
  "hackerone",
  "bugcrowd",
  "yeswehack",
  "intigriti",
  "private",
];

// Inline create-program dialog. Used as a nested dialog inside Create Run
// so the user can provision a program without leaving the run-creation
// flow. On success, the parent gets the new program and can proceed.
export function ProgramCreateDialog({
  open,
  onOpenChange,
  onCreated,
}: {
  open: boolean;
  onOpenChange: (v: boolean) => void;
  onCreated: (p: Program) => void;
}) {
  const create = useCreateProgram();

  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [vendor, setVendor] = useState("");
  const [vendorLink, setVendorLink] = useState("");
  const [scopeText, setScopeText] = useState("");
  const [errors, setErrors] = useState<Record<string, string>>({});

  function reset() {
    setName("");
    setDescription("");
    setVendor("");
    setVendorLink("");
    setScopeText("");
    setErrors({});
  }

  async function onSubmit() {
    const e: Record<string, string> = {};
    if (!name.trim()) e.name = "Name is required";
    else if (!SLUG_RE.test(name.trim()))
      e.name = "Lowercase a-z, 0-9, hyphens only (max 63 chars)";
    if (Object.keys(e).length > 0) {
      setErrors(e);
      return;
    }
    const scope = Array.from(
      new Set(
        scopeText
          .split(/[\n,]/)
          .map((s) => s.trim())
          .filter(Boolean),
      ),
    );
    try {
      const created = await create.mutateAsync({
        name: name.trim(),
        description: description.trim(),
        vendor: vendor.trim(),
        vendor_link: vendorLink.trim(),
        scope,
      });
      toast.success(`Program ${created.name} created`);
      onCreated(created);
      reset();
      onOpenChange(false);
    } catch (err) {
      toast.error("Create failed", { description: String(err) });
    }
  }

  return (
    <Dialog
      open={open}
      onOpenChange={(v) => {
        if (!v) reset();
        onOpenChange(v);
      }}
    >
      <DialogContent className="sm:max-w-2xl">
        <DialogHeader>
          <DialogTitle>Create program</DialogTitle>
          <DialogDescription>
            Quick create — the new program will be selected for this run.
          </DialogDescription>
        </DialogHeader>

        <FieldGroup>
          <Field data-invalid={!!errors.name}>
            <FieldLabel htmlFor="prog-create-name">Name (slug)</FieldLabel>
            <Input
              id="prog-create-name"
              placeholder="income-sg"
              value={name}
              onChange={(e) => setName(e.target.value)}
              aria-invalid={!!errors.name}
              className="font-mono"
              autoFocus
            />
            <FieldDescription>
              Lowercase a-z, 0-9, hyphens. Immutable after creation.
            </FieldDescription>
            {errors.name && <FieldError errors={[{ message: errors.name }]} />}
          </Field>

          <Field>
            <FieldLabel>Description</FieldLabel>
            <Textarea
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              placeholder="Singapore insurance giant — primary scope is web + mobile API."
              className="min-h-[60px]"
            />
          </Field>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <Field>
              <FieldLabel>Vendor</FieldLabel>
              <Input
                list="prog-create-vendors"
                value={vendor}
                onChange={(e) => setVendor(e.target.value)}
                placeholder="hackerone"
                autoComplete="off"
              />
              <datalist id="prog-create-vendors">
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
                placeholder="https://hackerone.com/income"
              />
            </Field>
          </div>

          <Field>
            <FieldLabel>Scope</FieldLabel>
            <Textarea
              value={scopeText}
              onChange={(e) => setScopeText(e.target.value)}
              placeholder={"*.income.com.sg\napi.income.com.sg"}
              className="min-h-[100px] font-mono text-sm"
            />
            <FieldDescription>One asset per line.</FieldDescription>
          </Field>
        </FieldGroup>

        <DialogFooter>
          <Button variant="ghost" onClick={() => onOpenChange(false)}>
            Cancel
          </Button>
          <Button onClick={onSubmit} disabled={create.isPending}>
            {create.isPending ? "Creating…" : "Create program"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
