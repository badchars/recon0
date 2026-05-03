import { formatDistanceToNowStrict, formatDistanceStrict } from "date-fns";

export function formatRelative(iso: string | null | undefined): string {
  if (!iso) return "—";
  try {
    return formatDistanceToNowStrict(new Date(iso), { addSuffix: true });
  } catch {
    return iso;
  }
}

export function formatDuration(seconds: number | undefined): string {
  if (!seconds || seconds < 0) return "—";
  if (seconds < 60) return `${seconds}s`;
  const m = Math.floor(seconds / 60);
  const s = seconds % 60;
  if (m < 60) return s ? `${m}m ${s}s` : `${m}m`;
  const h = Math.floor(m / 60);
  const mm = m % 60;
  return mm ? `${h}h ${mm}m` : `${h}h`;
}

export function formatDurationBetween(
  fromIso: string | undefined,
  toIso: string | null | undefined,
): string {
  if (!fromIso) return "—";
  try {
    const to = toIso ? new Date(toIso) : new Date();
    return formatDistanceStrict(new Date(fromIso), to);
  } catch {
    return "—";
  }
}

export function formatNumber(n: number | undefined): string {
  if (n === undefined || n === null) return "—";
  return n.toLocaleString();
}
