"use client";

import { useEffect, useMemo, useState } from "react";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { z } from "zod";
import { toast } from "sonner";
import { Plus, Wand2 } from "lucide-react";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import {
  Field,
  FieldGroup,
  FieldLabel,
  FieldDescription,
  FieldError,
} from "@/components/ui/field";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Textarea } from "@/components/ui/textarea";
import { Button } from "@/components/ui/button";
import { useCreateRun, usePrograms } from "@/lib/api/hooks";
import { ProgramCreateDialog } from "@/components/programs/program-create-dialog";
import type { Program } from "@/lib/api/types";

const HOSTNAME_RE =
  /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/i;

function parseDomains(raw: string): string[] {
  return Array.from(
    new Set(
      raw
        .split(/[\s,]+/)
        .map((s) => s.trim().toLowerCase())
        .filter(Boolean),
    ),
  );
}

const schema = z.object({
  program: z.string().min(1, "Pick a program"),
  domainsRaw: z
    .string()
    .min(1, "At least one domain is required")
    .refine((v) => parseDomains(v).length > 0, "No valid domains")
    .refine(
      (v) => parseDomains(v).every((d) => HOSTNAME_RE.test(d)),
      "Invalid hostname (use bare host, no scheme/port)",
    ),
});

type FormValues = z.infer<typeof schema>;

export function CreateRunModal({
  open,
  onOpenChange,
  defaultProgram,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  /** When set, the program select is preselected (used by program dashboard). */
  defaultProgram?: string;
}) {
  const createRun = useCreateRun();
  const { data: programs } = usePrograms();
  const [submitting, setSubmitting] = useState(false);
  const [createProgOpen, setCreateProgOpen] = useState(false);

  const {
    register,
    handleSubmit,
    watch,
    setValue,
    reset,
    formState: { errors },
  } = useForm<FormValues>({
    resolver: zodResolver(schema),
    defaultValues: { program: defaultProgram ?? "", domainsRaw: "" },
  });

  // Sync defaultProgram if the modal is opened with a different value
  useEffect(() => {
    if (open && defaultProgram) {
      setValue("program", defaultProgram);
    }
  }, [open, defaultProgram, setValue]);

  const watchProgram = watch("program");
  const watchDomains = watch("domainsRaw");
  const domainCount = parseDomains(watchDomains || "").length;

  const selectedProgram = useMemo(
    () => (programs ?? []).find((p) => p.name === watchProgram),
    [programs, watchProgram],
  );

  function fillFromScope() {
    if (!selectedProgram) return;
    if (selectedProgram.scope.length === 0) {
      toast.warning("Program has no scope defined");
      return;
    }
    // Scope can contain bug-bounty notation (`*.example.com`, URLs, etc.)
    // but recon0 needs bare apex hostnames. Strip leading wildcards and
    // any URL fragments, dedupe.
    const cleaned = Array.from(
      new Set(
        selectedProgram.scope
          .map((s) =>
            s
              .trim()
              .toLowerCase()
              .replace(/^https?:\/\//, "")
              .replace(/^\*\./, "")
              .replace(/[/?#].*$/, "")
              .replace(/:\d+$/, ""),
          )
          .filter((s) => HOSTNAME_RE.test(s)),
      ),
    );
    if (cleaned.length === 0) {
      toast.warning("No scannable hostnames in scope", {
        description: "Scope contains only wildcards/URLs — type a bare hostname manually",
      });
      return;
    }
    setValue("domainsRaw", cleaned.join("\n"), {
      shouldValidate: true,
    });
    if (cleaned.length < selectedProgram.scope.length) {
      toast.info(
        `${cleaned.length}/${selectedProgram.scope.length} entries normalized to bare hostnames`,
      );
    }
  }

  function onProgramCreated(p: Program) {
    setValue("program", p.name, { shouldValidate: true });
  }

  async function onSubmit(values: FormValues) {
    const domains = parseDomains(values.domainsRaw);
    setSubmitting(true);
    let ok = 0;
    const failed: string[] = [];

    for (const d of domains) {
      try {
        await createRun.mutateAsync({ domain: d, program: values.program });
        ok++;
      } catch {
        failed.push(d);
      }
    }
    setSubmitting(false);

    if (ok > 0) {
      toast.success(
        `${ok}/${domains.length} run${ok > 1 ? "s" : ""} queued`,
        failed.length
          ? { description: `Failed: ${failed.join(", ")}` }
          : undefined,
      );
      reset({ program: defaultProgram ?? "", domainsRaw: "" });
      onOpenChange(false);
    } else {
      toast.error("All requests failed", {
        description: "Check API connectivity",
      });
    }
  }

  const noPrograms = (programs ?? []).length === 0;

  return (
    <>
      <Dialog open={open} onOpenChange={onOpenChange}>
        <DialogContent className="sm:max-w-lg">
          <DialogHeader>
            <DialogTitle>Create Run</DialogTitle>
            <DialogDescription>
              Run a recon pipeline against a program&apos;s assets.
            </DialogDescription>
          </DialogHeader>

          <form onSubmit={handleSubmit(onSubmit)}>
            <FieldGroup>
              <Field data-invalid={!!errors.program}>
                <FieldLabel>Program</FieldLabel>
                {noPrograms ? (
                  <div className="rounded-md border border-dashed p-3 text-sm text-muted-foreground">
                    No programs yet.{" "}
                    <button
                      type="button"
                      onClick={() => setCreateProgOpen(true)}
                      className="text-foreground underline underline-offset-2 hover:text-sky-400"
                    >
                      Create your first
                    </button>
                    .
                  </div>
                ) : (
                  <div className="flex gap-2">
                    <Select
                      value={watchProgram || undefined}
                      onValueChange={(v) =>
                        v && setValue("program", v, { shouldValidate: true })
                      }
                    >
                      <SelectTrigger
                        className="flex-1"
                        aria-invalid={!!errors.program}
                      >
                        <SelectValue placeholder="Pick a program…" />
                      </SelectTrigger>
                      <SelectContent>
                        {(programs ?? []).map((p) => (
                          <SelectItem key={p.name} value={p.name}>
                            {p.name}
                            {p.vendor ? (
                              <span className="text-muted-foreground ml-1">
                                · {p.vendor}
                              </span>
                            ) : null}
                          </SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                    <Button
                      type="button"
                      variant="outline"
                      onClick={() => setCreateProgOpen(true)}
                      title="Create new program"
                      className="shrink-0"
                    >
                      <Plus className="size-4" />
                    </Button>
                  </div>
                )}
                <input type="hidden" {...register("program")} />
                {errors.program && (
                  <FieldError errors={[{ message: errors.program.message }]} />
                )}
              </Field>

              <Field data-invalid={!!errors.domainsRaw}>
                <div className="flex items-center justify-between">
                  <FieldLabel htmlFor="domainsRaw">Domain(s)</FieldLabel>
                  {selectedProgram && selectedProgram.scope.length > 0 && (
                    <button
                      type="button"
                      onClick={fillFromScope}
                      className="text-[11px] text-sky-400 hover:underline inline-flex items-center gap-1"
                    >
                      <Wand2 className="size-3" /> Fill from scope (
                      {selectedProgram.scope.length})
                    </button>
                  )}
                </div>
                <Textarea
                  id="domainsRaw"
                  placeholder={"income.com.sg\napi.income.com.sg"}
                  className="min-h-[110px] font-mono text-sm"
                  aria-invalid={!!errors.domainsRaw}
                  {...register("domainsRaw")}
                />
                <FieldDescription>
                  Bare hostname per line (no scheme/port). Comma works too.
                </FieldDescription>
                {errors.domainsRaw && (
                  <FieldError
                    errors={[{ message: errors.domainsRaw.message }]}
                  />
                )}
              </Field>
            </FieldGroup>

            <DialogFooter className="mt-6">
              <Button
                type="button"
                variant="ghost"
                onClick={() => onOpenChange(false)}
                disabled={submitting}
              >
                Cancel
              </Button>
              <Button
                type="submit"
                disabled={submitting || domainCount === 0 || !watchProgram}
              >
                {submitting
                  ? "Submitting…"
                  : `Queue ${domainCount || ""} run${domainCount === 1 ? "" : "s"}`.trim()}
              </Button>
            </DialogFooter>
          </form>
        </DialogContent>
      </Dialog>

      <ProgramCreateDialog
        open={createProgOpen}
        onOpenChange={setCreateProgOpen}
        onCreated={onProgramCreated}
      />
    </>
  );
}
