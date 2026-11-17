import { cacheLife, cacheTag } from "next/cache";
import { LIFE, LIMITS, WINDOWS } from "./config";
import type { CveRecord } from "./parsers/cve";
import type { EuvdItem } from "./parsers/euvd";
import type { KevCatalog, KevEntry } from "./parsers/kev";
import { daysBetween } from "./parsers/util";
import { productName } from "./format";
import { getSightings, type Sighting } from "./sources/circl";
import { getCveRecord } from "./sources/cve";
import { getEpss } from "./sources/epss";
import { getEuvd } from "./sources/euvd";
import { getBreaches } from "./sources/hibp";
import { getKev } from "./sources/kev";
import { getNews } from "./sources/news";
import { SOURCE_NAMES } from "./sources/result";
import { buildItem } from "./item";
import type { Evidence, Radar, RadarItem, SourceStatus, Trending } from "./types";

async function mapLimit<T, R>(items: T[], limit: number, fn: (item: T) => Promise<R>): Promise<R[]> {
  const out: R[] = new Array(items.length);
  let next = 0;
  async function worker() {
    while (next < items.length) {
      const i = next++;
      out[i] = await fn(items[i]);
    }
  }
  await Promise.all(Array.from({ length: Math.min(limit, items.length) }, worker));
  return out;
}

const byScore = (a: RadarItem, b: RadarItem) => b.score - a.score || (b.kev?.added ?? "").localeCompare(a.kev?.added ?? "");

export async function getRadar(): Promise<Radar> {
  "use cache";
  cacheTag("radar");
  const asOf = new Date().toISOString();

  const [kevRes, euvdRes, circlRes, breachRes, newsRes] = await Promise.all([
    getKev(),
    getEuvd(),
    getSightings(),
    getBreaches(),
    getNews(),
  ]);

  const kev: KevCatalog | null = kevRes.ok ? kevRes.data : null;
  const kevByCve = new Map((kev?.entries ?? []).map((e) => [e.cve, e]));
  const recentKev = (kev?.entries ?? []).filter((e) => daysBetween(e.added, asOf) <= WINDOWS.nowDays).slice(0, 60);

  const euvd = euvdRes.ok ? euvdRes.data : { critical: [], exploited: [] };
  const trending: Sighting[] = circlRes.ok ? circlRes.data.trending : [];
  const exploitedSightings: Sighting[] = circlRes.ok ? circlRes.data.exploited.filter((s) => s.count >= 2) : [];
  const sightingsByCve = new Map(trending.map((s) => [s.cve, s.count]));

  // Non-KEV candidates, keyed by CVE.
  type Candidate = { cve: string; euvd: EuvdItem | null; evidence: Evidence[] };
  const candidates = new Map<string, Candidate>();
  const addCandidate = (cve: string, euvdItem: EuvdItem | null, evidence: Evidence[] = []) => {
    if (kevByCve.has(cve)) return;
    const existing = candidates.get(cve);
    if (existing) {
      existing.euvd ??= euvdItem;
      for (const e of evidence) if (!existing.evidence.includes(e)) existing.evidence.push(e);
    } else {
      candidates.set(cve, { cve, euvd: euvdItem, evidence: [...evidence] });
    }
  };
  for (const item of euvd.exploited) for (const cve of item.cves.slice(0, 1)) addCandidate(cve, item, ["enisa"]);
  for (const s of exploitedSightings.slice(0, 15)) addCandidate(s.cve, null, ["circl-exploited"]);
  const criticalSorted = [...euvd.critical].sort(
    (a, b) => (b.published ?? "").localeCompare(a.published ?? "") || (b.score ?? 0) - (a.score ?? 0),
  );
  for (const item of criticalSorted.slice(0, 60)) for (const cve of item.cves.slice(0, 1)) addCandidate(cve, item);
  for (const s of trending.slice(0, 20)) addCandidate(s.cve, null);

  // Enrichment: EPSS for everything, CVE records for the items we will show.
  const allCves = [...recentKev.map((e) => e.cve), ...candidates.keys(), ...trending.map((t) => t.cve)];
  const epssRes = await getEpss(allCves);
  const epss = epssRes.ok ? epssRes.data : {};

  const recordTargets = [...recentKev.map((e) => e.cve), ...candidates.keys()].slice(0, LIMITS.cveRecords);
  const recordResults = await mapLimit(recordTargets, 12, (cve) => getCveRecord(cve));
  const records = new Map<string, CveRecord>();
  recordResults.forEach((r) => {
    if (r.ok) records.set(r.data.id, r.data);
  });

  const kevItems = recentKev.map((entry) =>
    buildItem({
      cve: entry.cve,
      kev: entry,
      record: records.get(entry.cve) ?? null,
      epss: epss[entry.cve] ?? null,
      sightings: sightingsByCve.get(entry.cve) ?? null,
      asOf,
    }),
  );
  const otherItems = [...candidates.values()].map((c) =>
    buildItem({
      cve: c.cve,
      euvd: c.euvd,
      record: records.get(c.cve) ?? null,
      epss: epss[c.cve] ?? null,
      sightings: sightingsByCve.get(c.cve) ?? null,
      extraEvidence: c.evidence,
      asOf,
    }),
  );
  // Items without any description or severity are noise (usually unparsed trending IDs).
  const usable = [...kevItems, ...otherItems].filter((i) => i.kev || i.cvss || i.summary);

  const now = usable.filter((i) => i.tier === "now").sort(byScore).slice(0, LIMITS.now);
  const soon = usable.filter((i) => i.tier === "soon").sort(byScore).slice(0, LIMITS.soon);
  const watch = usable
    .filter((i) => i.tier === "watch" && (i.cvss?.score ?? 0) >= 9)
    .sort(byScore)
    .slice(0, LIMITS.watch);

  const freshNow = now.filter((i) => i.kev && daysBetween(i.kev.added, asOf) <= 14);
  const top = (freshNow.length ? freshNow : now)[0] ?? soon[0] ?? null;

  const itemByCve = new Map(usable.filter((i) => i.cve).map((i) => [i.cve as string, i]));
  const trendingOut: Trending[] = trending.slice(0, LIMITS.trending).map((s) => {
    const known = itemByCve.get(s.cve);
    const kevEntry = kevByCve.get(s.cve);
    const record = records.get(s.cve);
    const label =
      known
        ? productName(known.vendor, known.product) || known.title
        : kevEntry
          ? productName(kevEntry.vendor, kevEntry.product)
          : record
            ? productName(record.vendor, record.product) || record.title
            : "";
    return { cve: s.cve, count: s.count, label, tier: known?.tier ?? (kevEntry ? "now" : null) };
  });

  const cveStatus: SourceStatus = {
    id: "cve",
    name: SOURCE_NAMES.cve,
    ok: recordTargets.length === 0 || records.size > 0,
    checkedAt: asOf,
    count: records.size,
    ...(recordTargets.length > 0 && records.size === 0
      ? { error: recordResults.find((r) => !r.ok)?.status.error ?? "no records" }
      : {}),
  };

  const statuses = [kevRes.status, cveStatus, epssRes.status, euvdRes.status, circlRes.status, breachRes.status, newsRes.status];
  const entries = kev?.entries ?? [];
  const radar: Radar = {
    generatedAt: asOf,
    statuses,
    top,
    now,
    soon,
    watch,
    trending: trendingOut,
    breaches: breachRes.ok ? breachRes.data : [],
    news: newsRes.ok ? newsRes.data : [],
    counts: {
      kevTotal: entries.length,
      kevLast7: entries.filter((e) => daysBetween(e.added, asOf) <= 7).length,
      kevLast30: entries.filter((e) => daysBetween(e.added, asOf) <= 30).length,
      ransomwareLast30: entries.filter((e) => e.ransomware && daysBetween(e.added, asOf) <= 30).length,
    },
  };

  // If the backbone source failed, try again soon instead of serving a thin page for 15 minutes.
  cacheLife(kevRes.ok && (euvdRes.ok || epssRes.ok) ? LIFE.radar : LIFE.retry);
  return radar;
}

export type CveDetail = {
  id: string;
  item: RadarItem | null;
  record: CveRecord | null;
  kev: KevEntry | null;
  statuses: SourceStatus[];
  asOf: string;
};

/** Everything for /cve/[id]. */
export async function getCveDetail(id: string): Promise<CveDetail> {
  "use cache";
  const cve = id.toUpperCase();
  cacheTag(`cve-${cve}`);
  const asOf = new Date().toISOString();
  const [recordRes, kevRes, epssRes] = await Promise.all([getCveRecord(cve), getKev(), getEpss([cve])]);
  const record = recordRes.ok ? recordRes.data : null;
  const kevEntry = kevRes.ok ? (kevRes.data.entries.find((e) => e.cve === cve) ?? null) : null;
  const epss = epssRes.ok ? (epssRes.data[cve] ?? null) : null;
  const item = record || kevEntry ? buildItem({ cve, record, kev: kevEntry, epss, asOf }) : null;
  cacheLife(recordRes.ok && kevRes.ok ? LIFE.slow : LIFE.retry);
  return { id: cve, item, record, kev: kevEntry, statuses: [recordRes.status, kevRes.status, epssRes.status], asOf };
}

/** Recently listed KEV CVEs: prerendered detail pages and the sitemap. */
export async function getRecentKevIds(limit: number): Promise<string[]> {
  "use cache";
  const res = await getKev();
  cacheLife(res.ok ? LIFE.radar : LIFE.retry);
  return res.ok ? res.data.entries.slice(0, limit).map((e) => e.cve) : [];
}

/** Compact KEV list for in-browser stack matching: [cve, vendor, product, name, added, ransomware]. */
export async function getKevIndex(): Promise<{
  version: string;
  generatedAt: string;
  rows: Array<[string, string, string, string, string, 0 | 1]>;
} | null> {
  "use cache";
  const res = await getKev();
  cacheLife(res.ok ? LIFE.radar : LIFE.retry);
  if (!res.ok) return null;
  return {
    version: res.data.version,
    generatedAt: new Date().toISOString(),
    rows: res.data.entries.map((e) => [e.cve, e.vendor, e.product, e.name, e.added, e.ransomware ? 1 : 0]),
  };
}
