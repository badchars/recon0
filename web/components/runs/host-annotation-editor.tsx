"use client";

import { useEffect, useRef, useState } from "react";
import { toast } from "sonner";
import { Textarea } from "@/components/ui/textarea";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Label } from "@/components/ui/label";
import {
  useHostAnnotations,
  useUpsertHostAnnotation,
} from "@/lib/api/hooks";
import { normalizeHostname } from "@/lib/host";
import type { ReviewStatus } from "@/lib/api/types";

const DEBOUNCE_MS = 600;

// Inline editor for a host's review status + description.
//
// Save is debounced — typing into the textarea kicks off a single PUT after
// the user pauses. The select fires immediately because it's a discrete
// action. Save uses optimistic concurrency: we send the version from the
// last server response; on 409 we silently re-fetch and the user sees the
// updated values on next keystroke.
export function HostAnnotationEditor({ hostname }: { hostname: string }) {
  const canon = normalizeHostname(hostname);
  const { data: annotations } = useHostAnnotations();
  const upsert = useUpsertHostAnnotation();

  const stored = annotations?.[canon];
  const storedDescription = stored?.description ?? "";
  const storedStatus: ReviewStatus = stored?.review_status ?? "not_reviewed";
  const storedVersion = stored?.version ?? 0;

  const [description, setDescription] = useState(storedDescription);
  const [status, setStatus] = useState<ReviewStatus>(storedStatus);

  // Reconcile local state with refreshed server data — only when the user
  // isn't actively editing (focus check) so we don't clobber typing.
  const textareaRef = useRef<HTMLTextAreaElement>(null);
  useEffect(() => {
    const isEditing = textareaRef.current === document.activeElement;
    if (!isEditing && storedDescription !== description) {
      setDescription(storedDescription);
    }
    if (storedStatus !== status) setStatus(storedStatus);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [storedDescription, storedStatus]);

  // Debounce text saves
  const debounceRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  useEffect(() => {
    if (description === storedDescription) return;
    if (debounceRef.current) clearTimeout(debounceRef.current);
    debounceRef.current = setTimeout(() => {
      upsert.mutate(
        {
          hostname: canon,
          description,
          review_status: status,
          expected_version: storedVersion,
        },
        {
          onError: (err) => toast.error("Save failed", { description: String(err) }),
        },
      );
    }, DEBOUNCE_MS);
    return () => {
      if (debounceRef.current) clearTimeout(debounceRef.current);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [description]);

  function changeStatus(next: ReviewStatus) {
    setStatus(next);
    upsert.mutate(
      {
        hostname: canon,
        description,
        review_status: next,
        expected_version: storedVersion,
      },
      {
        onError: (err) => toast.error("Save failed", { description: String(err) }),
      },
    );
  }

  return (
    <div className="space-y-2">
      <div className="flex items-center gap-3">
        <Label className="text-xs text-muted-foreground w-24 shrink-0">
          Review status
        </Label>
        <Select value={status} onValueChange={(v) => v && changeStatus(v as ReviewStatus)}>
          <SelectTrigger className="w-[180px] h-8">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="not_reviewed">Not reviewed</SelectItem>
            <SelectItem value="reviewing">Reviewing</SelectItem>
            <SelectItem value="reviewed">Reviewed</SelectItem>
          </SelectContent>
        </Select>
        {upsert.isPending && (
          <span className="text-[10px] text-muted-foreground">saving…</span>
        )}
      </div>
      <div className="flex items-start gap-3">
        <Label className="text-xs text-muted-foreground w-24 shrink-0 pt-2">
          Notes
        </Label>
        <Textarea
          ref={textareaRef}
          value={description}
          onChange={(e) => setDescription(e.target.value)}
          placeholder="Manual review notes — observations, next steps…"
          className="min-h-[70px] text-xs"
        />
      </div>
    </div>
  );
}
