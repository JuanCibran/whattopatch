import type { Breach } from "../types";
import { firstSentence, num, str, stripHtml, toIso } from "./util";

/** Have I Been Pwned /api/v3/breaches (or a single object from /latestbreach). */
export function parseBreaches(raw: unknown): Breach[] {
  const list = Array.isArray(raw) ? raw : raw && typeof raw === "object" ? [raw] : null;
  if (!list) throw new Error("HIBP response is not a breach list");
  const out: Breach[] = [];
  for (const b of list as Array<Record<string, unknown>>) {
    const name = str(b.Name);
    if (!name) continue;
    // Skip records HIBP marks as fabricated, spam lists, or sensitive.
    if (b.IsFabricated === true || b.IsSpamList === true || b.IsSensitive === true) continue;
    out.push({
      name,
      title: str(b.Title) || name,
      domain: str(b.Domain),
      breachDate: str(b.BreachDate) || null,
      addedDate: toIso(b.AddedDate),
      pwnCount: num(b.PwnCount) ?? 0,
      dataClasses: Array.isArray(b.DataClasses) ? b.DataClasses.map((d) => str(d)).filter(Boolean) : [],
      verified: b.IsVerified === true,
      summary: firstSentence(stripHtml(str(b.Description)), 200),
    });
  }
  return out.sort((a, b) => (b.addedDate ?? "").localeCompare(a.addedDate ?? ""));
}
