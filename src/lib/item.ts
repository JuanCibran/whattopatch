import { buildAdvice } from "./advice";
import type { CveRecord } from "./parsers/cve";
import type { EuvdItem } from "./parsers/euvd";
import type { KevEntry } from "./parsers/kev";
import { daysBetween, truncate } from "./parsers/util";
import { matchText } from "./stack";
import { categoryOf, priorityScore, tierFor } from "./triage";
import type { Epss, Evidence, RadarItem } from "./types";

export type ItemInput = {
  cve: string | null;
  euvd?: EuvdItem | null;
  kev?: KevEntry | null;
  record?: CveRecord | null;
  epss?: Epss | null;
  sightings?: number | null;
  extraEvidence?: Evidence[];
  asOf: string;
};

/** Combines everything we know about one vulnerability into a ranked item with advice. */
export function buildItem(input: ItemInput): RadarItem {
  const { kev, record, euvd, asOf } = input;
  const vendor = clean(kev?.vendor) || clean(record?.vendor) || clean(euvd?.vendor);
  const product = clean(kev?.product) || clean(record?.product) || clean(euvd?.product);
  const title =
    kev?.name || record?.title || truncate(record?.description || euvd?.description || "Untitled vulnerability", 110);
  const summary = truncate(kev?.description || record?.description || euvd?.description || "", 320);
  const published = record?.published ?? euvd?.published ?? null;
  const kevInfo = kev
    ? { added: kev.added, due: kev.due, ransomware: kev.ransomware, forensic: kev.forensic }
    : record?.kevAdded
      ? { added: record.kevAdded, due: "", ransomware: false, forensic: false }
      : null;

  const evidence = new Set<Evidence>(input.extraEvidence ?? []);
  if (kevInfo) evidence.add("cisa-kev");
  if (record?.ssvc?.exploitation === "active") evidence.add("cisa-ssvc");

  const cvss =
    record?.cvss ??
    (euvd?.score != null ? { score: euvd.score, severity: null, version: euvd.scoreVersion, vector: euvd.vector } : null);
  const fixed = [...new Set((record?.affected ?? []).flatMap((a) => a.fixed))].slice(0, 6);
  const vendorAdvisory =
    kev?.advisories[0] ?? record?.references.find((r) => r.tags.includes("vendor-advisory"))?.url ?? null;
  const advisory = vendorAdvisory ?? record?.references[0]?.url ?? euvd?.references[0] ?? null;

  const text = matchText(vendor, product, title);
  const category = categoryOf(text);
  const since = kevInfo?.added || published;
  const signals = {
    kev: kevInfo,
    evidence: [...evidence].filter((e) => e !== "cisa-kev"),
    epss: input.epss ?? null,
    ssvc: record?.ssvc ?? null,
    cvss,
    ageDays: since ? Math.max(0, daysBetween(since, asOf)) : null,
    category,
  };
  const tier = tierFor(signals);
  const id = input.cve ?? euvd?.euvdId ?? "unknown";

  return {
    id,
    cve: input.cve,
    euvd: euvd?.euvdId ?? null,
    tier,
    score: priorityScore(signals),
    vendor,
    product,
    title,
    summary,
    published,
    kev: kevInfo,
    evidence: [...evidence],
    epss: input.epss ?? null,
    cvss,
    ssvc: record?.ssvc ?? null,
    sightings: input.sightings ?? null,
    fixed,
    advisory,
    advice: buildAdvice({
      tier,
      kev: kevInfo,
      evidence: [...evidence],
      epss: input.epss ?? null,
      ssvc: record?.ssvc ?? null,
      cvss,
      category,
      vendor,
      product,
      fixed,
      advisory,
      advisoryIsVendor: Boolean(vendorAdvisory),
      asOf,
    }),
    matchText: text,
  };
}

function clean(value: string | null | undefined): string {
  const v = (value ?? "").trim();
  return /^(n\/a|na|unknown|unspecified|-)$/i.test(v) ? "" : v;
}
