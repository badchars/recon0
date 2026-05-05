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

// Bucket-split a single scope entry. Leading "*." marks a wildcard
// (the apex below it gets enumerated); anything else is treated as a
// fixed host (probed as-is, no subdomain enum). URL/port/path
// fragments are stripped before classification.
function classifyScopeEntry(
  raw: string,
): { kind: "wildcard" | "fixed"; host: string } | null {
  const stripped = raw
    .trim()
    .toLowerCase()
    .replace(/^https?:\/\//, "")
    .replace(/[/?#].*$/, "")
    .replace(/:\d+$/, "");
  if (!stripped) return null;
  if (stripped.startsWith("*.")) {
    const host = stripped.slice(2);
    return HOSTNAME_RE.test(host) ? { kind: "wildcard", host } : null;
  }
  return HOSTNAME_RE.test(stripped) ? { kind: "fixed", host: stripped } : null;
}

const hostsField = z
  .string()
  .refine(
    (v) => parseDomains(v).every((d) => HOSTNAME_RE.test(d)),
    "Invalid hostname (bare host only — no scheme, port, or *. prefix)",
  );

const schema = z
  .object({
    program: z.string().min(1, "Pick a program"),
    wildcardsRaw: hostsField,
    fixedHostsRaw: hostsField,
  })
  .refine(
    (v) =>
      parseDomains(v.wildcardsRaw).length + parseDomains(v.fixedHostsRaw).length >
      0,
    { message: "At least one host required", path: ["wildcardsRaw"] },
  );

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
    defaultValues: {
      program: defaultProgram ?? "",
      wildcardsRaw: "",
      fixedHostsRaw: "",
    },
  });

  useEffect(() => {
    if (open && defaultProgram) {
      setValue("program", defaultProgram);
    }
  }, [open, defaultProgram, setValue]);

  const watchProgram = watch("program");
  const watchWildcards = watch("wildcardsRaw");
  const watchFixed = watch("fixedHostsRaw");
  const wildcardCount = parseDomains(watchWildcards || "").length;
  const fixedCount = parseDomains(watchFixed || "").length;
  const totalCount = wildcardCount + fixedCount;

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
    const wildcards = new Set<string>();
    const fixed = new Set<string>();
    let skipped = 0;
    for (const entry of selectedProgram.scope) {
      const classified = classifyScopeEntry(entry);
      if (!classified) {
        skipped++;
        continue;
      }
      if (classified.kind === "wildcard") wildcards.add(classified.host);
      else fixed.add(classified.host);
    }
    if (wildcards.size === 0 && fixed.size === 0) {
      toast.warning("No scannable hostnames in scope", {
        description: "Add hosts manually below.",
      });
      return;
    }
    setValue("wildcardsRaw", Array.from(wildcards).sort().join("\n"), {
      shouldValidate: true,
    });
    setValue("fixedHostsRaw", Array.from(fixed).sort().join("\n"), {
      shouldValidate: true,
    });
    toast.success(
      `${wildcards.size} wildcards · ${fixed.size} fixed hosts`,
      skipped > 0 ? { description: `${skipped} entries skipped` } : undefined,
    );
  }

  function onProgramCreated(p: Program) {
    setValue("program", p.name, { shouldValidate: true });
  }

  async function onSubmit(values: FormValues) {
    const wildcards = parseDomains(values.wildcardsRaw);
    const fixed_hosts = parseDomains(values.fixedHostsRaw);
    setSubmitting(true);
    try {
      const res = await createRun.mutateAsync({
        program: values.program,
        wildcards,
        fixed_hosts,
      });
      toast.success(`Run queued (${res.queue_id})`, {
        description: `${wildcards.length} wildcards · ${fixed_hosts.length} fixed hosts`,
      });
      reset({
        program: defaultProgram ?? "",
        wildcardsRaw: "",
        fixedHostsRaw: "",
      });
      onOpenChange(false);
    } catch (err) {
      toast.error("Could not queue run", {
        description: err instanceof Error ? err.message : "Check API",
      });
    } finally {
      setSubmitting(false);
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

              <div className="flex items-center justify-between">
                <span className="text-xs text-muted-foreground">
                  Hosts ({totalCount})
                </span>
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

              <Field data-invalid={!!errors.wildcardsRaw}>
                <FieldLabel htmlFor="wildcardsRaw">
                  Wildcards{" "}
                  <span className="text-muted-foreground font-normal">
                    ({wildcardCount})
                  </span>
                </FieldLabel>
                <Textarea
                  id="wildcardsRaw"
                  placeholder={"target.com\nexample.org"}
                  className="min-h-[80px] font-mono text-sm"
                  aria-invalid={!!errors.wildcardsRaw}
                  {...register("wildcardsRaw")}
                />
                <FieldDescription>
                  Apex hosts to enumerate subdomains from (subfinder + amass).
                </FieldDescription>
                {errors.wildcardsRaw && (
                  <FieldError
                    errors={[{ message: errors.wildcardsRaw.message }]}
                  />
                )}
              </Field>

              <Field data-invalid={!!errors.fixedHostsRaw}>
                <FieldLabel htmlFor="fixedHostsRaw">
                  Fixed hosts{" "}
                  <span className="text-muted-foreground font-normal">
                    ({fixedCount})
                  </span>
                </FieldLabel>
                <Textarea
                  id="fixedHostsRaw"
                  placeholder={"admin.target.com\nvpn.target.com"}
                  className="min-h-[80px] font-mono text-sm"
                  aria-invalid={!!errors.fixedHostsRaw}
                  {...register("fixedHostsRaw")}
                />
                <FieldDescription>
                  Probe these exact hosts; skip subdomain enum.
                </FieldDescription>
                {errors.fixedHostsRaw && (
                  <FieldError
                    errors={[{ message: errors.fixedHostsRaw.message }]}
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
                disabled={submitting || totalCount === 0 || !watchProgram}
              >
                {submitting ? "Submitting…" : "Queue run"}
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
