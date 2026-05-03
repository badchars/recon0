"use client";

import { useRouter } from "next/navigation";
import Link from "next/link";
import { useEffect, useState } from "react";
import { ArrowLeft, ClipboardCopy, Save, Trash2 } from "lucide-react";
import { toast } from "sonner";
import { Button, buttonVariants } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
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
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { MarkdownEditor } from "@/components/vulnerabilities/markdown-editor";
import {
  useCreateVuln,
  useDeleteVuln,
  usePrograms,
  useUpdateVuln,
  useVulnerability,
} from "@/lib/api/hooks";
import { cn } from "@/lib/utils";
import {
  SUBMISSION_STATUSES,
  type Severity,
  type SubmissionStatus,
  type Vulnerability,
} from "@/lib/api/types";

const SEVERITIES: Severity[] = ["critical", "high", "medium", "low", "info"];

interface FormState {
  title: string;
  severity: Severity;
  submission_status: SubmissionStatus;
  bounty: string; // string for input ergonomics; coerced on save
  program: string;
  asset: string;
  description: string;
  tags: string[];
  references: string[];
}

function emptyForm(): FormState {
  return {
    title: "",
    severity: "medium",
    submission_status: "wait",
    bounty: "",
    program: "",
    asset: "",
    description: "",
    tags: [],
    references: [],
  };
}

function fromVuln(v: Vulnerability): FormState {
  return {
    title: v.title,
    severity: v.severity,
    submission_status: v.submission_status,
    bounty: v.bounty > 0 ? String(v.bounty) : "",
    program: v.program ?? "",
    asset: v.asset,
    description: v.description,
    tags: v.tags,
    references: v.references,
  };
}

export function VulnForm({ id }: { id?: string }) {
  const router = useRouter();
  const editing = !!id;
  const existing = useVulnerability(id);
  const { data: programs } = usePrograms();
  const create = useCreateVuln();
  const update = useUpdateVuln();
  const remove = useDeleteVuln();

  const [form, setForm] = useState<FormState>(emptyForm());
  const [errors, setErrors] = useState<Record<string, string>>({});
  const [tagInput, setTagInput] = useState("");
  const [refInput, setRefInput] = useState("");
  const [confirmDelete, setConfirmDelete] = useState(false);

  useEffect(() => {
    if (editing && existing.data) {
      setForm(fromVuln(existing.data));
    }
  }, [editing, existing.data]);

  const selectedProgram = (programs ?? []).find((p) => p.name === form.program);
  const scopeOptions = selectedProgram?.scope ?? [];

  function setField<K extends keyof FormState>(k: K, v: FormState[K]) {
    setForm((s) => ({ ...s, [k]: v }));
  }

  function validate(): boolean {
    const e: Record<string, string> = {};
    if (!form.title.trim()) e.title = "Title is required";
    if (!form.asset.trim()) e.asset = "Asset is required";
    if (form.bounty && isNaN(Number(form.bounty))) e.bounty = "Must be a number";
    setErrors(e);
    return Object.keys(e).length === 0;
  }

  async function onSave() {
    if (!validate()) return;
    const body = {
      title: form.title.trim(),
      severity: form.severity,
      submission_status: form.submission_status,
      bounty: Number(form.bounty || 0),
      asset: form.asset.trim(),
      program: form.program.trim() || undefined,
      description: form.description,
      tags: form.tags,
      references: form.references,
    };

    if (editing && existing.data) {
      try {
        await update.mutateAsync({
          id: existing.data.id,
          ...body,
          expected_version: existing.data.version,
        });
        toast.success("Vulnerability updated");
        router.push("/vulnerabilities");
      } catch (err) {
        toast.error("Save failed", { description: String(err) });
      }
    } else {
      try {
        const created = await create.mutateAsync(body);
        toast.success("Vulnerability created");
        router.replace(`/vulnerabilities/${created.id}`);
      } catch (err) {
        toast.error("Create failed", { description: String(err) });
      }
    }
  }

  async function onDelete() {
    if (!id) return;
    try {
      await remove.mutateAsync(id);
      toast.success("Vulnerability deleted");
      router.push("/vulnerabilities");
    } catch (err) {
      toast.error("Delete failed", { description: String(err) });
    }
  }

  // F7 — render the form's current state as a self-contained markdown
  // report ready for HackerOne / Bugcrowd / YesWeHack.
  async function copyAsMarkdown() {
    const lines: string[] = [];
    const sevUpper = form.severity.toUpperCase();
    lines.push(`## [${sevUpper}] ${form.title.trim() || "(untitled)"}`);
    lines.push("");
    if (form.asset) lines.push(`**Asset:** \`${form.asset}\`  `);
    if (form.program) {
      const prog = (programs ?? []).find((p) => p.name === form.program);
      const vendorPart = prog?.vendor ? ` (${prog.vendor})` : "";
      lines.push(`**Program:** ${form.program}${vendorPart}  `);
    }
    if (form.bounty && Number(form.bounty) > 0) {
      lines.push(`**Bounty:** $${Number(form.bounty).toLocaleString()}  `);
    }
    lines.push(`**Status:** ${form.submission_status}`);
    lines.push("");
    if (form.description.trim()) {
      lines.push(form.description.trim());
      lines.push("");
    }
    if (form.tags.length > 0) {
      lines.push(`**Tags:** ${form.tags.map((t) => `\`${t}\``).join(", ")}`);
      lines.push("");
    }
    if (form.references.length > 0) {
      lines.push("### References");
      lines.push("");
      for (const r of form.references) lines.push(`- ${r}`);
      lines.push("");
    }

    const md = lines.join("\n");
    try {
      await navigator.clipboard.writeText(md);
      toast.success("Copied as Markdown", {
        description: "Paste into HackerOne / Bugcrowd / YesWeHack report.",
      });
    } catch {
      toast.error("Clipboard write failed", {
        description: "Browser denied clipboard access — copy manually.",
      });
    }
  }

  function addTag() {
    const t = tagInput.trim().toLowerCase();
    if (!t || form.tags.includes(t)) return;
    setField("tags", [...form.tags, t]);
    setTagInput("");
  }

  function addRef() {
    const r = refInput.trim();
    if (!r || form.references.includes(r)) return;
    setField("references", [...form.references, r]);
    setRefInput("");
  }

  if (editing && existing.isLoading) {
    return <div className="p-6 text-sm text-muted-foreground">Loading vulnerability…</div>;
  }
  if (editing && existing.isError) {
    return (
      <div className="p-6 space-y-4">
        <Link
          href="/vulnerabilities"
          className={cn(buttonVariants({ variant: "ghost", size: "sm" }), "gap-1 -ml-2")}
        >
          <ArrowLeft className="size-3.5" /> Vulnerabilities
        </Link>
        <p className="text-sm text-destructive">Vulnerability not found.</p>
      </div>
    );
  }

  return (
    <div className="p-6 space-y-6 max-w-5xl">
      <div className="flex items-center gap-2">
        <Link
          href="/vulnerabilities"
          className={cn(buttonVariants({ variant: "ghost", size: "sm" }), "gap-1 -ml-2")}
        >
          <ArrowLeft className="size-3.5" /> Vulnerabilities
        </Link>
      </div>

      <div className="flex items-center justify-between gap-2">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight">
            {editing ? `Edit ${id}` : "New Vulnerability"}
          </h1>
          {editing && existing.data && (
            <p className="text-xs text-muted-foreground font-mono mt-0.5">
              {existing.data.id}
            </p>
          )}
        </div>
        <div className="flex items-center gap-2">
          <Button
            variant="outline"
            size="sm"
            onClick={copyAsMarkdown}
            className="gap-1"
            title="Copy as ready-to-paste bug bounty report"
          >
            <ClipboardCopy className="size-3.5" /> Copy as MD
          </Button>
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
        <Field data-invalid={!!errors.title}>
          <FieldLabel htmlFor="vuln-title">Title</FieldLabel>
          <Input
            id="vuln-title"
            placeholder="AWS access keys leaked in app.bundle.js"
            value={form.title}
            onChange={(e) => setField("title", e.target.value)}
            aria-invalid={!!errors.title}
          />
          {errors.title && <FieldError errors={[{ message: errors.title }]} />}
        </Field>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          <Field>
            <FieldLabel>Severity</FieldLabel>
            <Select
              value={form.severity}
              onValueChange={(v) => v && setField("severity", v as Severity)}
            >
              <SelectTrigger>
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {SEVERITIES.map((s) => (
                  <SelectItem key={s} value={s}>
                    {s}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </Field>

          <Field>
            <FieldLabel>Submission status</FieldLabel>
            <Select
              value={form.submission_status}
              onValueChange={(v) => v && setField("submission_status", v as SubmissionStatus)}
            >
              <SelectTrigger>
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {SUBMISSION_STATUSES.map((s) => (
                  <SelectItem key={s} value={s}>
                    {s}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </Field>

          <Field data-invalid={!!errors.bounty}>
            <FieldLabel htmlFor="vuln-bounty">Bounty (USD)</FieldLabel>
            <div className="flex items-center gap-1">
              <span className="text-muted-foreground text-sm">$</span>
              <Input
                id="vuln-bounty"
                type="number"
                inputMode="decimal"
                placeholder="0"
                value={form.bounty}
                onChange={(e) => setField("bounty", e.target.value)}
                aria-invalid={!!errors.bounty}
              />
            </div>
            {errors.bounty && <FieldError errors={[{ message: errors.bounty }]} />}
          </Field>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <Field>
            <FieldLabel>Program</FieldLabel>
            <Select
              value={form.program || "__none__"}
              onValueChange={(v) => {
                const next = v === "__none__" ? "" : v ?? "";
                setField("program", next);
                // Reset asset when program changes — different scope
                setField("asset", "");
              }}
            >
              <SelectTrigger>
                <SelectValue placeholder="(none)" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="__none__">(none)</SelectItem>
                {(programs ?? []).map((p) => (
                  <SelectItem key={p.name} value={p.name}>
                    {p.name}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
            <FieldDescription>
              Optional. Drives the asset dropdown via the program&apos;s scope.
            </FieldDescription>
          </Field>

          <Field data-invalid={!!errors.asset}>
            <FieldLabel htmlFor="vuln-asset">Asset</FieldLabel>
            {scopeOptions.length > 0 ? (
              <Select
                value={form.asset || "__custom__"}
                onValueChange={(v) => v && setField("asset", v === "__custom__" ? "" : v)}
              >
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {scopeOptions.map((a) => (
                    <SelectItem key={a} value={a}>
                      {a}
                    </SelectItem>
                  ))}
                  <SelectItem value="__custom__">— custom —</SelectItem>
                </SelectContent>
              </Select>
            ) : null}
            {(scopeOptions.length === 0 || form.asset === "" || !scopeOptions.includes(form.asset)) && (
              <Input
                id="vuln-asset"
                placeholder="api.income.com.sg"
                value={form.asset}
                onChange={(e) => setField("asset", e.target.value)}
                aria-invalid={!!errors.asset}
                className="font-mono"
              />
            )}
            <FieldDescription>
              {scopeOptions.length > 0
                ? "Pick from the program scope, or type a custom value."
                : "Hostname, URL, or asset identifier."}
            </FieldDescription>
            {errors.asset && <FieldError errors={[{ message: errors.asset }]} />}
          </Field>
        </div>

        <Field>
          <FieldLabel>Tags</FieldLabel>
          <div className="flex gap-2">
            <Input
              placeholder="add tag…"
              value={tagInput}
              onChange={(e) => setTagInput(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === "Enter") {
                  e.preventDefault();
                  addTag();
                }
              }}
            />
            <Button type="button" variant="outline" onClick={addTag}>
              Add
            </Button>
          </div>
          {form.tags.length > 0 && (
            <div className="flex flex-wrap gap-1.5 pt-2">
              {form.tags.map((t) => (
                <Badge
                  key={t}
                  variant="secondary"
                  className="cursor-pointer"
                  onClick={() =>
                    setField(
                      "tags",
                      form.tags.filter((x) => x !== t),
                    )
                  }
                >
                  {t} ✕
                </Badge>
              ))}
            </div>
          )}
        </Field>

        <Field>
          <FieldLabel>Description</FieldLabel>
          <FieldDescription>
            Single markdown field — write summary, PoC, evidence with your own
            headings. Paste or drop screenshots to upload them inline (Cmd+V).
            {!editing && " Image upload available after the first save."}
          </FieldDescription>
          <MarkdownEditor
            value={form.description}
            onChange={(v) => setField("description", v)}
            height={500}
            vulnID={editing ? id : undefined}
          />
        </Field>

        <Field>
          <FieldLabel>References</FieldLabel>
          <div className="flex gap-2">
            <Input
              placeholder="https://..."
              value={refInput}
              onChange={(e) => setRefInput(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === "Enter") {
                  e.preventDefault();
                  addRef();
                }
              }}
            />
            <Button type="button" variant="outline" onClick={addRef}>
              Add
            </Button>
          </div>
          {form.references.length > 0 && (
            <ul className="text-sm space-y-1 pt-2">
              {form.references.map((r) => (
                <li key={r} className="flex items-center gap-2">
                  <a
                    href={r}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="text-sky-400 hover:underline truncate max-w-md"
                  >
                    {r}
                  </a>
                  <button
                    type="button"
                    className="text-xs text-muted-foreground hover:text-destructive"
                    onClick={() =>
                      setField(
                        "references",
                        form.references.filter((x) => x !== r),
                      )
                    }
                  >
                    remove
                  </button>
                </li>
              ))}
            </ul>
          )}
        </Field>
      </FieldGroup>

      <Dialog open={confirmDelete} onOpenChange={setConfirmDelete}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Delete vulnerability?</DialogTitle>
            <DialogDescription>
              The vulnerability and any uploaded screenshots will be permanently
              removed.
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
