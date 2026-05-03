import { Badge } from "@/components/ui/badge";
import { cn } from "@/lib/utils";
import type { ReviewStatus } from "@/lib/api/types";

const VARIANT: Record<
  ReviewStatus,
  { label: string; className: string }
> = {
  not_reviewed: {
    label: "not reviewed",
    className: "border-border text-muted-foreground",
  },
  reviewing: {
    label: "reviewing",
    className: "border-amber-500/50 text-amber-300 bg-amber-500/5",
  },
  reviewed: {
    label: "reviewed",
    className: "border-emerald-500/40 text-emerald-400 bg-emerald-500/5",
  },
};

export function ReviewBadge({
  status,
  className,
}: {
  status: ReviewStatus;
  className?: string;
}) {
  const v = VARIANT[status] ?? VARIANT.not_reviewed;
  return (
    <Badge
      variant="outline"
      className={cn("text-[10px]", v.className, className)}
    >
      {v.label}
    </Badge>
  );
}
