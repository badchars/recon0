"use client";

import dynamic from "next/dynamic";
import { useCallback, useEffect, useRef, useState } from "react";
import { toast } from "sonner";
import "@uiw/react-md-editor/markdown-editor.css";
import "@uiw/react-markdown-preview/markdown.css";
import { recon0 } from "@/lib/api/recon0";

const MDEditor = dynamic(() => import("@uiw/react-md-editor"), {
  ssr: false,
  loading: () => (
    <div className="rounded-md border bg-muted/20 h-[260px] flex items-center justify-center text-xs text-muted-foreground">
      Loading editor…
    </div>
  ),
});

interface Props {
  value: string;
  onChange: (v: string) => void;
  height?: number;
  /** When set, paste/drop image events upload to this vuln's attachment endpoint
   *  and the resulting markdown reference is inserted at cursor. */
  vulnID?: string;
}

// Inserts text at the current selection in a textarea-like element.
function insertAt(textarea: HTMLTextAreaElement, snippet: string): string {
  const before = textarea.value.slice(0, textarea.selectionStart);
  const after = textarea.value.slice(textarea.selectionEnd);
  return before + snippet + after;
}

const ALLOWED_PASTE_MIME = ["image/png", "image/jpeg", "image/webp", "image/gif"];

export function MarkdownEditor({ value, onChange, height = 320, vulnID }: Props) {
  const [mounted, setMounted] = useState(false);
  const containerRef = useRef<HTMLDivElement>(null);
  useEffect(() => setMounted(true), []);

  const uploadAndInsert = useCallback(
    async (file: File | Blob, fallbackName: string) => {
      if (!vulnID) {
        toast.error("Save the vulnerability first to enable image uploads");
        return;
      }
      const t = toast.loading("Uploading image…");
      try {
        const filename = (file as File).name || fallbackName;
        const res = await recon0.uploadVulnAttachment(vulnID, file, filename);
        const alt = filename.replace(/\.[a-z0-9]+$/i, "");
        const snippet = `\n\n![${alt}](${res.url})\n\n`;
        // Find the underlying textarea inside the MDEditor and inject at caret.
        const textarea = containerRef.current?.querySelector(
          "textarea",
        ) as HTMLTextAreaElement | null;
        if (textarea) {
          const next = insertAt(textarea, snippet);
          onChange(next);
        } else {
          onChange(value + snippet);
        }
        toast.success("Image uploaded", { id: t });
      } catch (err) {
        toast.error("Upload failed", { id: t, description: String(err) });
      }
    },
    [onChange, value, vulnID],
  );

  // onPaste: detect clipboard images and upload them. Allow text paste through.
  const onPaste = useCallback(
    (e: React.ClipboardEvent<HTMLDivElement>) => {
      const items = e.clipboardData?.items;
      if (!items) return;
      for (let i = 0; i < items.length; i++) {
        const item = items[i];
        if (item.kind === "file" && ALLOWED_PASTE_MIME.includes(item.type)) {
          const file = item.getAsFile();
          if (file) {
            e.preventDefault();
            void uploadAndInsert(file, `pasted-${Date.now()}.png`);
            return;
          }
        }
      }
    },
    [uploadAndInsert],
  );

  // onDrop: same flow for dropped image files.
  const onDrop = useCallback(
    (e: React.DragEvent<HTMLDivElement>) => {
      const files = e.dataTransfer?.files;
      if (!files || files.length === 0) return;
      const imgs = Array.from(files).filter((f) =>
        ALLOWED_PASTE_MIME.includes(f.type),
      );
      if (imgs.length === 0) return;
      e.preventDefault();
      imgs.forEach((f) => void uploadAndInsert(f, f.name));
    },
    [uploadAndInsert],
  );

  if (!mounted) return null;

  return (
    <div
      ref={containerRef}
      data-color-mode="dark"
      className="rounded-md overflow-hidden border"
      onPaste={onPaste}
      onDrop={onDrop}
    >
      <MDEditor
        value={value}
        onChange={(v) => onChange(v ?? "")}
        height={height}
        preview="edit"
      />
    </div>
  );
}
