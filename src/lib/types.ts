export type SourceId = "kev" | "cve" | "epss" | "euvd" | "circl" | "hibp" | "news";

export type SourceStatus = {
  id: SourceId;
  name: string;
  ok: boolean;
  /** Plain-language reason when `ok` is false. */
  error?: string;
  /** ISO timestamp of the attempt. */
  checkedAt: string;
  /** Freshness reported by the source itself, when it has one (KEV release time, EPSS model date). */
  sourceUpdatedAt?: string;
  count?: number;
};

export type SourceResult<T> =
  | { ok: true; data: T; status: SourceStatus }
  | { ok: false; data: null; status: SourceStatus };

export type Tier = "now" | "soon" | "watch";

export type Ssvc = {
  exploitation: "none" | "poc" | "active" | null;
  automatable: "yes" | "no" | null;
  impact: "partial" | "total" | null;
};

export type Cvss = {
  score: number;
  severity: string | null;
  version: string | null;
  vector: string | null;
};

export type Epss = {
  /** Probability of exploitation in the next 30 days, 0..1. */
  score: number;
  /** Share of all scored CVEs with an equal or lower score, 0..1. */
  percentile: number;
  date: string;
};

export type KevInfo = {
  added: string;
  due: string;
  ransomware: boolean;
  forensic: boolean;
};

export type Evidence = "cisa-kev" | "enisa" | "circl-exploited" | "cisa-ssvc";

export type AdviceStep = {
  title: string;
  detail: string;
  href?: string;
  hrefLabel?: string;
};

export type Advice = {
  /** One sentence: why this tier. */
  why: string;
  steps: AdviceStep[];
};

export type RadarItem = {
  /** CVE ID when known, otherwise the EUVD ID. */
  id: string;
  cve: string | null;
  euvd: string | null;
  tier: Tier;
  score: number;
  vendor: string;
  product: string;
  title: string;
  summary: string;
  published: string | null;
  kev: KevInfo | null;
  evidence: Evidence[];
  epss: Epss | null;
  cvss: Cvss | null;
  ssvc: Ssvc | null;
  sightings: number | null;
  fixed: string[];
  advisory: string | null;
  advice: Advice;
  /** Lowercased "vendor | product | title" used for stack matching. */
  matchText: string;
};

export type Breach = {
  name: string;
  title: string;
  domain: string;
  breachDate: string | null;
  addedDate: string | null;
  pwnCount: number;
  dataClasses: string[];
  verified: boolean;
  summary: string;
};

export type NewsItem = {
  title: string;
  url: string;
  source: string;
  published: string | null;
  cves: string[];
};

export type Trending = {
  cve: string;
  count: number;
  label: string;
  tier: Tier | null;
};

export type Radar = {
  generatedAt: string;
  statuses: SourceStatus[];
  top: RadarItem | null;
  now: RadarItem[];
  soon: RadarItem[];
  watch: RadarItem[];
  trending: Trending[];
  breaches: Breach[];
  news: NewsItem[];
  counts: {
    kevTotal: number;
    kevLast7: number;
    kevLast30: number;
    ransomwareLast30: number;
  };
};
