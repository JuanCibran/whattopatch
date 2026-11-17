// Deterministic formatting (fixed locale and UTC) so server and browser render the same text.

const dayMonth = new Intl.DateTimeFormat("en-US", { month: "short", day: "numeric", timeZone: "UTC" });
const dayMonthYear = new Intl.DateTimeFormat("en-US", { month: "short", day: "numeric", year: "numeric", timeZone: "UTC" });
const longDate = new Intl.DateTimeFormat("en-US", {
  weekday: "long",
  month: "long",
  day: "numeric",
  year: "numeric",
  timeZone: "UTC",
});
const clock = new Intl.DateTimeFormat("en-US", { hour: "2-digit", minute: "2-digit", hour12: false, timeZone: "UTC" });

function parse(iso: string | null | undefined): Date | null {
  if (!iso) return null;
  const t = Date.parse(iso);
  return Number.isFinite(t) ? new Date(t) : null;
}

/** "Nov 16", or "Nov 16, 2025" when the year differs from `relativeTo`. */
export function fmtDate(iso: string | null | undefined, relativeTo?: string): string {
  const d = parse(iso);
  if (!d) return "";
  const ref = parse(relativeTo ?? null);
  if (ref && ref.getUTCFullYear() === d.getUTCFullYear()) return dayMonth.format(d);
  return dayMonthYear.format(d);
}

export function fmtLongDate(iso: string | null | undefined): string {
  const d = parse(iso);
  return d ? longDate.format(d) : "";
}

export function fmtClock(iso: string | null | undefined): string {
  const d = parse(iso);
  return d ? `${clock.format(d)} UTC` : "";
}

/** EPSS probability as a short percentage: 0.9412 → "94%", 0.042 → "4.2%", 0.0004 → "<0.1%". */
export function fmtProbability(p: number): string {
  const pct = p * 100;
  if (pct >= 10) return `${Math.round(pct)}%`;
  if (pct >= 0.1) return `${pct.toFixed(1).replace(/\.0$/, "")}%`;
  return "<0.1%";
}

export function fmtPercentile(p: number): string {
  return `${Math.min(99, Math.floor(p * 100))}%`;
}

export function fmtCount(n: number): string {
  if (n >= 1_000_000_000) return `${(n / 1_000_000_000).toFixed(1).replace(/\.0$/, "")} billion`;
  if (n >= 1_000_000) return `${(n / 1_000_000).toFixed(1).replace(/\.0$/, "")} million`;
  return n.toLocaleString("en-US");
}

/** "a, b or c" */
export function orList(items: string[]): string {
  if (items.length <= 1) return items[0] ?? "";
  return `${items.slice(0, -1).join(", ")} or ${items[items.length - 1]}`;
}

/** "Barracuda Networks" + "Barracuda Email Security Gateway" reads as just the product. */
export function productName(vendor: string, product: string): string {
  const v = vendor.trim();
  const p = product.trim();
  if (!p) return v;
  if (!v) return p;
  if (/^multiple products$/i.test(p)) return `${v} (multiple products)`;
  const first = v.split(/\s+/)[0].toLowerCase();
  if (p.toLowerCase().startsWith(first)) return p;
  return `${v} ${p}`;
}
