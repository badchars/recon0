"use client";

import { useRouter } from "next/navigation";
import Link from "next/link";
import { useEffect, useState } from "react";
import { ArrowLeft, Check, ClipboardCopy, Save, Send, Trash2 } from "lucide-react";
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
import { copyImageAsPng } from "@/lib/clipboard/rich-report";
import {
  Sheet,
  SheetContent,
  SheetDescription,
  SheetFooter,
  SheetHeader,
  SheetTitle,
} from "@/components/ui/sheet";
import { Progress } from "@/components/ui/progress";
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

  // Submit wizard state.
  const [submitOpen, setSubmitOpen] = useState(false);
  const [submitQueue, setSubmitQueue] = useState<{ url: string; alt: string }[]>(
    [],
  );
  const [textCopied, setTextCopied] = useState(false);
  const [copiedImages, setCopiedImages] = useState<Set<number>>(new Set());
  const [activeImage, setActiveImage] = useState(0);

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

  const IMG_RE = /!\[([^\]]*)\]\(([^)]+)\)/g;

  // Image references in the description, in document order (duplicates kept) —
  // each maps 1:1 to a numbered placeholder in the copied text and a paste step.
  function listImages(): { url: string; alt: string }[] {
    const out: { url: string; alt: string }[] = [];
    const re = new RegExp(IMG_RE.source, "g");
    let m: RegExpExecArray | null;
    while ((m = re.exec(form.description))) out.push({ alt: m[1], url: m[2] });
    return out;
  }

  // Render the form's current state as a self-contained markdown report.
  // Image references are swapped for numbered placeholders: their localhost
  // URLs are unreachable by the target platform, so we leave a "paste here" marker
  // and the images are pasted separately as real bytes (see the submit wizard).
  function buildReportMarkdown(): string {
    let imgN = 0;
    const description = form.description.replace(
      new RegExp(IMG_RE.source, "g"),
      (_m, alt: string) => {
        imgN += 1;
        const caption = alt ? `${alt} — ` : "";
        return `> 📎 [ screenshot ${imgN} — ${caption}paste image here ]`;
      },
    );

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
    if (description.trim()) {
      lines.push(description.trim());
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
    return lines.join("\n");
  }

  // ── Submit: guided paste wizard ──
  // The clipboard carries one payload per paste, so submitting a report with N
  // screenshots is unavoidably 1 text paste + N image pastes. This walks the
  // user through that sequence — copy report text, then each image in order,
  // auto-advancing — so it becomes a steady copy → switch → paste rhythm.

  async function openSubmit() {
    const imgs = listImages();
    setSubmitQueue(imgs);
    setCopiedImages(new Set());
    setTextCopied(false);
    setActiveImage(imgs.length > 0 ? 1 : 0);
    setSubmitOpen(true);
    // Auto-copy the report text first (still inside the click gesture).
    try {
      await navigator.clipboard.writeText(buildReportMarkdown());
      setTextCopied(true);
      toast.success("Report text copied", {
        description:
          "Paste into the report editor (Cmd+V), then copy each screenshot.",
      });
    } catch {
      toast.error("Clipboard blocked", {
        description: "Use the “Copy report text” button in the panel.",
      });
    }
  }

  async function copyReportText() {
    try {
      await navigator.clipboard.writeText(buildReportMarkdown());
      setTextCopied(true);
      toast.success("Report text copied", {
        description: "Paste into the report editor (Cmd+V).",
      });
    } catch {
      toast.error("Clipboard write failed");
    }
  }

  async function copyStepImage(n: number) {
    const img = submitQueue[n - 1];
    if (!img) return;
    const t = toast.loading(`Copying image ${n}…`);
    try {
      await copyImageAsPng(img.url);
      const copied = new Set(copiedImages).add(n);
      setCopiedImages(copied);
      // Advance to the next not-yet-copied image, if any.
      let next = 0;
      for (let i = 1; i <= submitQueue.length; i++) {
        if (!copied.has(i)) {
          next = i;
          break;
        }
      }
      setActiveImage(next);
      toast.success(`Image ${n} copied`, {
        id: t,
        description: `Paste at marker [${n}] (Cmd+V).`,
      });
    } catch (err) {
      toast.error(`Image ${n} failed`, { id: t, description: String(err) });
    }
  }

  function resetSubmit() {
    setCopiedImages(new Set());
    setActiveImage(submitQueue.length > 0 ? 1 : 0);
    void copyReportText();
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
            size="sm"
            onClick={openSubmit}
            className="gap-1"
            title="Guided paste: copies your report text, then each screenshot in order"
          >
            <Send className="size-3.5" /> Submit
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

      <Sheet open={submitOpen} onOpenChange={setSubmitOpen}>
        <SheetContent side="right" className="w-full sm:max-w-md">
          <SheetHeader>
            <SheetTitle className="flex items-center gap-2">
              <Send className="size-4" /> Submit report
            </SheetTitle>
            <SheetDescription>
              Paste these into the report editor in order. One paste each —
              that&apos;s a clipboard limit, not a bug.
            </SheetDescription>
          </SheetHeader>

          <div className="flex-1 space-y-2 overflow-y-auto px-4">
            {/* Step 0 — report text */}
            <div
              className={cn(
                "rounded-md border p-3",
                textCopied ? "bg-muted/20" : "border-primary",
              )}
            >
              <div className="flex items-center gap-2 text-sm font-medium">
                {textCopied ? (
                  <Check className="size-4 text-green-500" />
                ) : (
                  <span className="flex size-4 items-center justify-center rounded-full border text-[10px]">
                    0
                  </span>
                )}
                Report text
              </div>
              <p className="mt-1 text-xs text-muted-foreground">
                {textCopied
                  ? "Copied — paste this into the report editor first (Cmd+V)."
                  : "Copy the report text, then paste it into the editor."}
              </p>
              <Button
                variant="outline"
                size="sm"
                className="mt-2 gap-1"
                onClick={copyReportText}
              >
                <ClipboardCopy className="size-3.5" />
                {textCopied ? "Re-copy report text" : "Copy report text"}
              </Button>
            </div>

            {/* Image steps */}
            {submitQueue.map((img, i) => {
              const n = i + 1;
              const isDone = copiedImages.has(n);
              const isActive = activeImage === n;
              const name = decodeURIComponent(
                img.url.split("/").pop() ?? img.url,
              );
              return (
                <div
                  key={`${img.url}-${n}`}
                  className={cn(
                    "rounded-md border p-3",
                    isActive
                      ? "border-primary"
                      : isDone
                        ? "bg-muted/20"
                        : "",
                  )}
                >
                  <div className="flex items-center gap-2">
                    {isDone ? (
                      <Check className="size-4 shrink-0 text-green-500" />
                    ) : (
                      <span className="flex size-4 shrink-0 items-center justify-center rounded-full border text-[10px]">
                        {n}
                      </span>
                    )}
                    {/* eslint-disable-next-line @next/next/no-img-element */}
                    <img
                      src={img.url}
                      alt={name}
                      className="size-9 rounded object-cover"
                    />
                    <span
                      className="min-w-0 flex-1 truncate text-xs text-muted-foreground"
                      title={name}
                    >
                      {name}
                    </span>
                  </div>
                  {isActive ? (
                    <>
                      <Button
                        size="sm"
                        className="mt-2 w-full gap-1"
                        onClick={() => copyStepImage(n)}
                      >
                        <ClipboardCopy className="size-3.5" /> Copy image {n} of{" "}
                        {submitQueue.length}
                      </Button>
                      <p className="mt-1 text-center text-xs text-muted-foreground">
                        then paste at marker [{n}] (Cmd+V)
                      </p>
                    </>
                  ) : (
                    <Button
                      variant="ghost"
                      size="sm"
                      className="mt-2 gap-1"
                      onClick={() => copyStepImage(n)}
                    >
                      <ClipboardCopy className="size-3.5" />
                      {isDone ? "Re-copy" : `Copy image ${n}`}
                    </Button>
                  )}
                </div>
              );
            })}

            {textCopied && copiedImages.size === submitQueue.length && (
              <div className="rounded-md border border-green-500/40 bg-green-500/5 p-3">
                <div className="flex items-center gap-2 text-sm font-medium">
                  <Check className="size-4 text-green-500" /> Ready to submit
                </div>
                <p className="mt-1 text-xs text-muted-foreground">
                  {submitQueue.length > 0
                    ? `Report text + all ${submitQueue.length} screenshot(s) copied & pasted.`
                    : "Report copied — paste it and submit."}
                </p>
              </div>
            )}
          </div>

          <SheetFooter>
            <div className="flex items-center justify-between text-xs text-muted-foreground">
              <span>
                {copiedImages.size} / {submitQueue.length} images pasted
              </span>
            </div>
            <Progress
              value={
                submitQueue.length === 0
                  ? textCopied
                    ? 100
                    : 0
                  : Math.round((copiedImages.size / submitQueue.length) * 100)
              }
            />
            <div className="flex gap-2">
              <Button
                variant="ghost"
                size="sm"
                className="flex-1"
                onClick={resetSubmit}
              >
                Start over
              </Button>
              <Button
                size="sm"
                className="flex-1"
                onClick={() => setSubmitOpen(false)}
              >
                Done
              </Button>
            </div>
          </SheetFooter>
        </SheetContent>
      </Sheet>
    </div>
  );
}
