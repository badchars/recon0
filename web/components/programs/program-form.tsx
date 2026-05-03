"use client";

import Link from "next/link";
import { useRouter } from "next/navigation";
import { useEffect, useState } from "react";
import { ArrowLeft, ExternalLink, Save, Trash2 } from "lucide-react";
import { toast } from "sonner";
import { Button, buttonVariants } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import {
  Field,
  FieldGroup,
  FieldLabel,
  FieldDescription,
  FieldError,
} from "@/components/ui/field";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import {
  useCreateProgram,
  useDeleteProgram,
  useProgram,
  useUpdateProgram,
} from "@/lib/api/hooks";
import { cn } from "@/lib/utils";

const SLUG_RE = /^[a-z0-9][a-z0-9-]{0,62}$/;
const VENDOR_SUGGESTIONS = [
  "hackerone",
  "bugcrowd",
  "yeswehack",
  "intigriti",
  "private",
];

interface FormState {
  name: string;
  description: string;
  vendor: string;
  vendor_link: string;
  scopeText: string; // textarea, line per asset
}

function emptyForm(): FormState {
  return {
    name: "",
    description: "",
    vendor: "",
    vendor_link: "",
    scopeText: "",
  };
}

function fromProgram(p: {
  name: string;
  description: string;
  vendor: string;
  vendor_link: string;
  scope: string[];
}): FormState {
  return {
    name: p.name,
    description: p.description,
    vendor: p.vendor,
    vendor_link: p.vendor_link,
    scopeText: p.scope.join("\n"),
  };
}

function parseScope(text: string): string[] {
  return Array.from(
    new Set(
      text
        .split(/[\n,]/)
        .map((s) => s.trim())
        .filter(Boolean),
    ),
  );
}

export function ProgramForm({
  name,
  defaultName,
}: {
  name?: string;
  /** Pre-fill the name field on the create form (used by run detail
   *  "+ Register" deep-link). Ignored when editing. */
  defaultName?: string;
}) {
  const editing = !!name;
  const router = useRouter();
  const existing = useProgram(name);

  const create = useCreateProgram();
  const update = useUpdateProgram();
  const remove = useDeleteProgram();

  const [form, setForm] = useState<FormState>(() => {
    const base = emptyForm();
    if (!name && defaultName) base.name = defaultName;
    return base;
  });
  const [errors, setErrors] = useState<Record<string, string>>({});
  const [confirmDelete, setConfirmDelete] = useState(false);

  useEffect(() => {
    if (editing && existing.data) {
      setForm(fromProgram(existing.data));
    }
  }, [editing, existing.data]);

  function setField<K extends keyof FormState>(k: K, v: FormState[K]) {
    setForm((s) => ({ ...s, [k]: v }));
  }

  function validate(): boolean {
    const e: Record<string, string> = {};
    if (!editing) {
      if (!form.name.trim()) {
        e.name = "Name is required";
      } else if (!SLUG_RE.test(form.name)) {
        e.name = "Lowercase letters, digits, and hyphens only (max 63 chars)";
      }
    }
    setErrors(e);
    return Object.keys(e).length === 0;
  }

  async function onSave() {
    if (!validate()) return;

    const scope = parseScope(form.scopeText);

    if (editing && existing.data) {
      try {
        await update.mutateAsync({
          name: existing.data.name,
          description: form.description.trim(),
          vendor: form.vendor.trim(),
          vendor_link: form.vendor_link.trim(),
          scope,
          expected_version: existing.data.version,
        });
        toast.success("Program updated");
        router.push("/programs");
      } catch (err) {
        toast.error("Save failed", { description: String(err) });
      }
    } else {
      try {
        const created = await create.mutateAsync({
          name: form.name.trim(),
          description: form.description.trim(),
          vendor: form.vendor.trim(),
          vendor_link: form.vendor_link.trim(),
          scope,
        });
        toast.success("Program created");
        router.replace(`/programs/${encodeURIComponent(created.name)}`);
      } catch (err) {
        toast.error("Create failed", { description: String(err) });
      }
    }
  }

  async function onDelete() {
    if (!editing || !name) return;
    try {
      await remove.mutateAsync(name);
      toast.success("Program deleted");
      router.push("/programs");
    } catch (err) {
      toast.error("Delete failed", { description: String(err) });
    }
  }

  if (editing && existing.isLoading) {
    return (
      <div className="p-6 text-sm text-muted-foreground">Loading program…</div>
    );
  }

  if (editing && existing.isError) {
    return (
      <div className="p-6 space-y-4">
        <Link
          href="/programs"
          className={cn(
            buttonVariants({ variant: "ghost", size: "sm" }),
            "gap-1 -ml-2",
          )}
        >
          <ArrowLeft className="size-3.5" /> Programs
        </Link>
        <p className="text-sm text-destructive">Program not found.</p>
      </div>
    );
  }

  return (
    <div className="p-6 space-y-6 max-w-3xl">
      <div className="flex items-center gap-2">
        <Link
          href="/programs"
          className={cn(
            buttonVariants({ variant: "ghost", size: "sm" }),
            "gap-1 -ml-2",
          )}
        >
          <ArrowLeft className="size-3.5" /> Programs
        </Link>
      </div>

      <div className="flex items-center justify-between gap-2">
        <h1 className="text-2xl font-semibold tracking-tight">
          {editing ? `Edit ${name}` : "New Program"}
        </h1>
        <div className="flex items-center gap-2">
          {editing && (
            <Button
              variant="destructive"
              size="sm"
              onClick={() => setConfirmDelete(true)}
              className="gap-1"
            >
              <Trash2 className="size-3.5" /> Delete
            </Button>
          )}
          <Button onClick={onSave} className="gap-1">
            <Save className="size-3.5" /> Save
          </Button>
        </div>
      </div>

      <FieldGroup>
        <Field data-invalid={!!errors.name}>
          <FieldLabel htmlFor="prog-name">Name (slug)</FieldLabel>
          <Input
            id="prog-name"
            placeholder="income-sg"
            value={form.name}
            onChange={(e) => setField("name", e.target.value)}
            disabled={editing}
            aria-invalid={!!errors.name}
            className="font-mono"
          />
          <FieldDescription>
            {editing
              ? "Name is immutable — used as the program identifier across runs and vulns."
              : "Lowercase a-z, 0-9, and hyphens. Max 63 chars."}
          </FieldDescription>
          {errors.name && <FieldError errors={[{ message: errors.name }]} />}
        </Field>

        <Field>
          <FieldLabel htmlFor="prog-desc">Description</FieldLabel>
          <Textarea
            id="prog-desc"
            value={form.description}
            onChange={(e) => setField("description", e.target.value)}
            placeholder="Singapore insurance giant — primary scope is web + mobile API."
            className="min-h-[80px]"
          />
        </Field>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <Field>
            <FieldLabel htmlFor="prog-vendor">Vendor</FieldLabel>
            <Input
              id="prog-vendor"
              list="vendor-suggestions"
              value={form.vendor}
              onChange={(e) => setField("vendor", e.target.value)}
              placeholder="hackerone"
              autoComplete="off"
            />
            <datalist id="vendor-suggestions">
              {VENDOR_SUGGESTIONS.map((v) => (
                <option key={v} value={v} />
              ))}
            </datalist>
          </Field>
          <Field>
            <FieldLabel htmlFor="prog-link">Vendor link</FieldLabel>
            <div className="flex gap-1">
              <Input
                id="prog-link"
                value={form.vendor_link}
                onChange={(e) => setField("vendor_link", e.target.value)}
                placeholder="https://hackerone.com/income"
              />
              {form.vendor_link && (
                <a
                  href={form.vendor_link}
                  target="_blank"
                  rel="noopener noreferrer"
                  className={cn(
                    buttonVariants({ variant: "outline", size: "sm" }),
                    "shrink-0",
                  )}
                >
                  <ExternalLink className="size-3.5" />
                </a>
              )}
            </div>
          </Field>
        </div>

        <Field>
          <FieldLabel htmlFor="prog-scope">Scope</FieldLabel>
          <Textarea
            id="prog-scope"
            value={form.scopeText}
            onChange={(e) => setField("scopeText", e.target.value)}
            placeholder={"*.income.com.sg\napi.income.com.sg"}
            className="min-h-[120px] font-mono text-sm"
          />
          <FieldDescription>
            One asset per line. Used as the asset dropdown in vulnerability
            editor.
          </FieldDescription>
        </Field>
      </FieldGroup>

      <Dialog open={confirmDelete} onOpenChange={setConfirmDelete}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Delete program?</DialogTitle>
            <DialogDescription>
              This will remove the program record. Existing vulnerabilities
              and runs that reference it stay intact (orphaned), but you
              won&apos;t be able to use the scope dropdown for new vulns.
            </DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button variant="ghost" onClick={() => setConfirmDelete(false)}>
              Cancel
            </Button>
            <Button variant="destructive" onClick={onDelete}>
              Delete
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
