import { num, str } from "./util";

export type Sighting = { cve: string; count: number };

/** CIRCL Vulnerability-Lookup /api/stats/vulnerability/most_sighted: [{ vulnerability, count }]. */
export function parseMostSighted(raw: unknown): Sighting[] {
  if (!Array.isArray(raw)) throw new Error("CIRCL response is not a list");
  const out: Sighting[] = [];
  for (const row of raw as Array<Record<string, unknown>>) {
    const id = str(row.vulnerability).toUpperCase();
    const count = num(row.count);
    if (!/^CVE-\d{4}-\d{4,}$/.test(id) || count == null) continue;
    if (!out.some((s) => s.cve === id)) out.push({ cve: id, count });
  }
  return out;
}
