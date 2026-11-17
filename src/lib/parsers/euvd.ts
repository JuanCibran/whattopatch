import { extractCves, num, str, toIso } from "./util";

/** ENISA European Vulnerability Database (EUVD). */
export type EuvdItem = {
  euvdId: string;
  cves: string[];
  description: string;
  published: string | null;
  updated: string | null;
  score: number | null;
  scoreVersion: string | null;
  vector: string | null;
  vendor: string | null;
  product: string | null;
  references: string[];
  exploitedSince: string | null;
  assigner: string | null;
};

/**
 * Handles both shapes the API returns: a bare array (convenience endpoints, max 8 records)
 * and `{ items, total }` (search). Dates arrive as "Oct 15, 2026, 8:30:32 PM";
 * `aliases` and `references` arrive as newline-separated strings.
 */
export function parseEuvdList(raw: unknown): EuvdItem[] {
  const list = Array.isArray(raw)
    ? raw
    : Array.isArray((raw as { items?: unknown })?.items)
      ? (raw as { items: unknown[] }).items
      : null;
  if (!list) throw new Error("EUVD response has no items");
  const out: EuvdItem[] = [];
  for (const entry of list as Array<Record<string, unknown>>) {
    const euvdId = str(entry.id);
    if (!euvdId) continue;
    const vendors = names(entry.enisaIdVendor, "vendor");
    const products = names(entry.enisaIdProduct, "product");
    out.push({
      euvdId,
      cves: extractCves(str(entry.aliases)),
      description: str(entry.description),
      published: toIso(entry.datePublished),
      updated: toIso(entry.dateUpdated),
      score: num(entry.baseScore),
      scoreVersion: str(entry.baseScoreVersion) || null,
      vector: str(entry.baseScoreVector) || null,
      vendor: vendors[0] ?? null,
      product: products[0] ?? null,
      references: (str(entry.references).match(/https?:\/\/\S+/g) ?? []).slice(0, 12),
      exploitedSince: toIso(entry.exploitedSince),
      assigner: str(entry.assigner) || null,
    });
  }
  return out;
}

function names(value: unknown, key: "vendor" | "product"): string[] {
  if (!Array.isArray(value)) return [];
  const out: string[] = [];
  for (const row of value as Array<Record<string, unknown>>) {
    const inner = row?.[key] as { name?: unknown } | undefined;
    const name = str(inner?.name);
    if (name && !out.includes(name)) out.push(name);
  }
  return out;
}
