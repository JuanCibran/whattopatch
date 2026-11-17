import type { Epss } from "../types";
import { CVE_ID_RE, num, str } from "./util";

/** FIRST EPSS API: { data: [{ cve, epss, percentile, date }] } with string values. */
export function parseEpss(raw: unknown): Record<string, Epss> {
  const data = (raw as { data?: unknown })?.data;
  if (!Array.isArray(data)) throw new Error("EPSS response has no data array");
  const out: Record<string, Epss> = {};
  for (const row of data as Array<Record<string, unknown>>) {
    const cve = str(row.cve).toUpperCase();
    const score = num(row.epss);
    const percentile = num(row.percentile);
    if (!CVE_ID_RE.test(cve) || score == null || percentile == null) continue;
    out[cve] = { score, percentile, date: str(row.date) };
  }
  return out;
}

/** The API accepts a comma-separated list; keep URLs well under common length limits. */
export function chunk<T>(items: T[], size: number): T[][] {
  const out: T[][] = [];
  for (let i = 0; i < items.length; i += size) out.push(items.slice(i, i + size));
  return out;
}
