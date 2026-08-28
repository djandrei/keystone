/** Human-readable file size: 1024-based, 0 decimals for bytes, 1 above.
 *  16120 -> "15.7 KB", 3_566_789 -> "3.4 MB", 820 -> "820 B", 0 -> "0 B".
 *  Bad input (negative / NaN / non-finite) -> "—". */
export function formatBytes(n: number): string {
  if (!Number.isFinite(n) || n < 0) return "—";
  if (n < 1024) return `${Math.round(n)} B`;
  const units = ["KB", "MB", "GB", "TB", "PB"];
  let value = n / 1024;
  let i = 0;
  while (value >= 1024 && i < units.length - 1) {
    value /= 1024;
    i += 1;
  }
  return `${value.toFixed(1)} ${units[i]}`;
}
