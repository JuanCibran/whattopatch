import type { Cvss, Ssvc } from "../types";
import { summarizeAffected, type AffectedSummary } from "./versions";
import { CVE_ID_RE, num, str, stripHtml } from "./util";

/** A CVE Record (JSON 5.x) from the CVE Program, reduced to what the app shows. */
export type CveRecord = {
  id: string;
  state: string;
  title: string;
  description: string;
  published: string | null;
  updated: string | null;
  assigner: string | null;
  vendor: string;
  product: string;
  affected: AffectedSummary[];
  cvss: Cvss | null;
  ssvc: Ssvc | null;
  /** CISA's ADP container says the CVE is in KEV (date added). */
  kevAdded: string | null;
  solutions: string[];
  workarounds: string[];
  references: Array<{ url: string; tags: string[]; name: string | null }>;
};

/** cvelistV5 layout: cves/<year>/<number without last 3 digits>xxx/<id>.json */
export function cveRecordPath(id: string): string | null {
  const m = id.toUpperCase().match(/^CVE-(\d{4})-(\d{4,})$/);
  if (!m) return null;
  const bucket = `${Math.floor(Number(m[2]) / 1000)}xxx`;
  return `cves/${m[1]}/${bucket}/CVE-${m[1]}-${m[2]}.json`;
}

type Container = Record<string, unknown> & {
  providerMetadata?: { shortName?: unknown };
  metrics?: Array<Record<string, unknown>>;
};

export function parseCveRecord(raw: unknown): CveRecord {
  const root = raw as {
    cveMetadata?: Record<string, unknown>;
    containers?: { cna?: Container; adp?: Container[] };
  };
  const meta = root?.cveMetadata;
  const id = str(meta?.cveId).toUpperCase();
  if (!meta || !CVE_ID_RE.test(id)) throw new Error("Not a CVE record");
  const cna: Container = root.containers?.cna ?? {};
  const adp: Container[] = Array.isArray(root.containers?.adp) ? root.containers!.adp! : [];
  const cisaAdp = adp.find((c) => str(c.providerMetadata?.shortName).toUpperCase() === "CISA-ADP");

  const affected = summarizeAffected(cna.affected);
  const firstAffected = Array.isArray(cna.affected) ? (cna.affected[0] as Record<string, unknown>) : undefined;

  return {
    id,
    state: str(meta.state),
    title: str(cna.title),
    description: englishText(cna.descriptions),
    published: str(meta.datePublished) || null,
    updated: str(meta.dateUpdated) || null,
    assigner: str(meta.assignerShortName) || null,
    vendor: str(firstAffected?.vendor),
    product: str(firstAffected?.product),
    affected,
    cvss: pickCvss(cna.metrics) ?? pickCvss(cisaAdp?.metrics),
    ssvc: pickSsvc(cisaAdp?.metrics),
    kevAdded: pickKevAdded(cisaAdp?.metrics),
    solutions: englishTexts(cna.solutions),
    workarounds: englishTexts(cna.workarounds),
    references: pickReferences(cna.references),
  };
}

function englishTexts(list: unknown): string[] {
  if (!Array.isArray(list)) return [];
  const rows = list as Array<{ lang?: unknown; value?: unknown }>;
  const english = rows.filter((r) => str(r.lang).toLowerCase().startsWith("en"));
  return (english.length ? english : rows)
    .map((r) => stripHtml(str(r.value)))
    .filter(Boolean)
    .slice(0, 4);
}

function englishText(list: unknown): string {
  return englishTexts(list)[0] ?? "";
}

const CVSS_KEYS = ["cvssV4_0", "cvssV3_1", "cvssV3_0", "cvssV2_0"] as const;

function pickCvss(metrics: unknown): Cvss | null {
  if (!Array.isArray(metrics)) return null;
  for (const key of CVSS_KEYS) {
    for (const m of metrics as Array<Record<string, unknown>>) {
      const c = m?.[key] as Record<string, unknown> | undefined;
      const score = num(c?.baseScore);
      if (c && score != null) {
        return {
          score,
          severity: str(c.baseSeverity).toUpperCase() || null,
          version: str(c.version) || key.replace("cvssV", "").replace("_", "."),
          vector: str(c.vectorString) || null,
        };
      }
    }
  }
  return null;
}

function otherOfType(metrics: unknown, type: string): Record<string, unknown> | null {
  if (!Array.isArray(metrics)) return null;
  for (const m of metrics as Array<Record<string, unknown>>) {
    const other = m?.other as { type?: unknown; content?: unknown } | undefined;
    if (str(other?.type).toLowerCase() === type && other?.content && typeof other.content === "object") {
      return other.content as Record<string, unknown>;
    }
  }
  return null;
}

function pickSsvc(metrics: unknown): Ssvc | null {
  const content = otherOfType(metrics, "ssvc");
  if (!content || !Array.isArray(content.options)) return null;
  const opts: Record<string, string> = {};
  for (const o of content.options as Array<Record<string, unknown>>) {
    for (const [k, v] of Object.entries(o)) opts[k.toLowerCase()] = str(v).toLowerCase();
  }
  const exploitation = opts["exploitation"];
  const automatable = opts["automatable"];
  const impact = opts["technical impact"];
  return {
    exploitation:
      exploitation === "active" || exploitation === "poc" || exploitation === "none" ? exploitation : null,
    automatable: automatable === "yes" || automatable === "no" ? automatable : null,
    impact: impact === "total" || impact === "partial" ? impact : null,
  };
}

function pickKevAdded(metrics: unknown): string | null {
  const content = otherOfType(metrics, "kev");
  return content ? str(content.dateAdded) || null : null;
}

function pickReferences(list: unknown): CveRecord["references"] {
  if (!Array.isArray(list)) return [];
  const out: CveRecord["references"] = [];
  for (const r of list as Array<Record<string, unknown>>) {
    const url = str(r.url);
    if (!/^https?:\/\//i.test(url) || out.some((x) => x.url === url)) continue;
    out.push({
      url,
      tags: Array.isArray(r.tags) ? r.tags.map((t) => str(t).toLowerCase()) : [],
      name: str(r.name) || null,
    });
  }
  // Vendor advisories and patches first.
  const rank = (tags: string[]) => (tags.includes("vendor-advisory") ? 0 : tags.includes("patch") ? 1 : 2);
  return out.sort((a, b) => rank(a.tags) - rank(b.tags)).slice(0, 15);
}
