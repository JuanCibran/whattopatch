export const CVE_ID_RE = /^CVE-\d{4}-\d{4,}$/;

export function str(v: unknown): string {
  return typeof v === "string" ? v.trim() : v == null ? "" : String(v).trim();
}

export function num(v: unknown): number | null {
  const n = typeof v === "number" ? v : typeof v === "string" && v.trim() !== "" ? Number(v) : NaN;
  return Number.isFinite(n) ? n : null;
}

export function extractCves(text: string): string[] {
  const found = text.toUpperCase().match(/CVE-\d{4}-\d{4,}/g) ?? [];
  return [...new Set(found)];
}

const NAMED_ENTITIES: Record<string, string> = {
  amp: "&",
  lt: "<",
  gt: ">",
  quot: '"',
  apos: "'",
  nbsp: " ",
  ndash: "–",
  mdash: "—",
  lsquo: "‘",
  rsquo: "’",
  ldquo: "“",
  rdquo: "”",
  hellip: "…",
};

export function decodeEntities(text: string): string {
  return text.replace(/&(#x[0-9a-f]+|#\d+|[a-z]+);/gi, (match, code: string) => {
    if (code[0] === "#") {
      const n = code[1].toLowerCase() === "x" ? parseInt(code.slice(2), 16) : parseInt(code.slice(1), 10);
      return Number.isFinite(n) && n > 0 && n < 0x110000 ? String.fromCodePoint(n) : match;
    }
    return NAMED_ENTITIES[code.toLowerCase()] ?? match;
  });
}

export function stripHtml(html: string): string {
  return decodeEntities(html.replace(/<br\s*\/?>/gi, "\n").replace(/<[^>]*>/g, " "))
    .replace(/[ \t\f\v]+/g, " ")
    .replace(/\s*\n\s*/g, "\n")
    .trim();
}

export function truncate(text: string, max: number): string {
  const clean = text.replace(/\s+/g, " ").trim();
  if (clean.length <= max) return clean;
  const cut = clean.slice(0, max - 1);
  const lastSpace = cut.lastIndexOf(" ");
  return `${(lastSpace > max * 0.5 ? cut.slice(0, lastSpace) : cut).replace(/[,;:.\s]+$/, "")}…`;
}

export function firstSentence(text: string, max = 220): string {
  const clean = text.replace(/\s+/g, " ").trim();
  const match = clean.match(/^(.+?[.!?])(\s|$)/);
  return truncate(match ? match[1] : clean, max);
}

/** ISO string or null. Accepts ISO and formats like "Oct 15, 2026, 8:30:32 PM" (EUVD). */
export function toIso(value: unknown): string | null {
  const s = str(value);
  if (!s) return null;
  // "Oct 15, 2026, 8:30:32 PM" (EUVD). Parsed explicitly as UTC so the result
  // doesn't depend on the server's time zone. \s also matches the narrow no-break
  // space some formatters put before AM/PM.
  const m = s.match(/^([A-Za-z]{3,9})\.?\s+(\d{1,2}),\s*(\d{4}),?\s+(\d{1,2}):(\d{2})(?::(\d{2}))?\s*([AP]M)?$/i);
  if (m) {
    const months = ["jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec"];
    const month = months.indexOf(m[1].slice(0, 3).toLowerCase());
    if (month < 0) return null;
    const rawHour = Number(m[4]);
    const meridiem = m[7]?.toUpperCase();
    const hour = meridiem === "PM" ? (rawHour % 12) + 12 : meridiem === "AM" ? rawHour % 12 : rawHour;
    const ms = Date.UTC(Number(m[3]), month, Number(m[2]), hour, Number(m[5]), Number(m[6] ?? 0));
    return Number.isFinite(ms) ? new Date(ms).toISOString() : null;
  }
  const direct = Date.parse(s);
  return Number.isFinite(direct) ? new Date(direct).toISOString() : null;
}

/** Whole days between two ISO dates (b - a), floored. */
export function daysBetween(aIso: string, bIso: string): number {
  return Math.floor((Date.parse(bIso) - Date.parse(aIso)) / 86_400_000);
}

export function uniq<T>(items: T[]): T[] {
  return [...new Set(items)];
}
