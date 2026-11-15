export function formatTimestamp(value: number | null): string {
  if (value === null || !Number.isSafeInteger(value) || value < 0)
    return "Not recorded";
  return new Intl.DateTimeFormat(undefined, {
    dateStyle: "medium",
    timeStyle: "medium",
    timeZone: "UTC",
  }).format(value);
}

export function formatRelative(value: number | null, now = Date.now()): string {
  if (value === null) return "Not recorded";
  const seconds = Math.round((value - now) / 1000);
  const absolute = Math.abs(seconds);
  const parts: Intl.RelativeTimeFormatUnit[] = [
    "second",
    "minute",
    "hour",
    "day",
  ];
  const divisors = [1, 60, 3_600, 86_400];
  let unitIndex = 0;
  for (let index = 1; index < divisors.length; index += 1) {
    if (absolute >= (divisors[index] ?? Number.POSITIVE_INFINITY))
      unitIndex = index;
  }
  const divisor = divisors[unitIndex] ?? 1;
  const unit = parts[unitIndex] ?? "second";
  return new Intl.RelativeTimeFormat(undefined, { numeric: "auto" }).format(
    Math.round(seconds / divisor),
    unit,
  );
}

export function formatBytes(value: number): string {
  if (!Number.isFinite(value) || value < 0) return "Not recorded";
  const units = ["B", "KiB", "MiB", "GiB", "TiB"];
  let size = value;
  let unit = 0;
  while (size >= 1_024 && unit < units.length - 1) {
    size /= 1_024;
    unit += 1;
  }
  return `${size.toFixed(unit === 0 ? 0 : 1)} ${units[unit]}`;
}

export function formatCount(value: number): string {
  return Number.isSafeInteger(value) && value >= 0
    ? new Intl.NumberFormat().format(value)
    : "Not recorded";
}

export function formatDuration(seconds: number): string {
  if (!Number.isFinite(seconds) || seconds < 0) return "Not recorded";
  const total = Math.floor(seconds);
  const days = Math.floor(total / 86_400);
  const hours = Math.floor((total % 86_400) / 3_600);
  const minutes = Math.floor((total % 3_600) / 60);
  const remainder = total % 60;
  if (days > 0) return `${days}d ${hours}h ${minutes}m`;
  if (hours > 0) return `${hours}h ${minutes}m`;
  if (minutes > 0) return `${minutes}m ${remainder}s`;
  return `${remainder}s`;
}

export function csvCell(value: string): string {
  const safe = /^[=+\-@\t\r]/.test(value) ? `'${value}` : value;
  return `"${safe.replaceAll('"', '""')}"`;
}
