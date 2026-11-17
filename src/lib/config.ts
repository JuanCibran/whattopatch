export const SITE = {
  name: "WhatToPatch",
  tagline: "What attackers are exploiting right now, and exactly what to do about it.",
  url: (process.env.NEXT_PUBLIC_SITE_URL ?? "https://whattopatch.vercel.app").replace(/\/$/, ""),
  repo: process.env.NEXT_PUBLIC_REPO_URL ?? "",
};

/** Sent with every upstream request. Several sources (HIBP, CIRCL) ask clients to identify themselves. */
export const USER_AGENT = `WhatToPatch/0.1 (+${SITE.url})`;

/**
 * Cache lifetimes (seconds) for `cacheLife()`.
 * - radar: the main page and the sources that feed it refresh every 15 minutes.
 * - slow: data that changes a few times a day.
 * - daily: data published once a day (EPSS) or rarely edited (CVE records).
 * - retry: used when a source fails, so the page tries again within a couple of minutes.
 */
export const LIFE = {
  radar: { stale: 300, revalidate: 900, expire: 86_400 },
  slow: { stale: 300, revalidate: 3_600, expire: 86_400 },
  daily: { stale: 300, revalidate: 21_600, expire: 172_800 },
  retry: { stale: 300, revalidate: 120, expire: 3_600 },
} as const;

export const WINDOWS = {
  /** KEV additions newer than this are listed in "Now". */
  nowDays: 30,
  /** EUVD critical vulnerabilities published within this window feed "This week" and "Watch". */
  criticalDays: 7,
  /** CIRCL sightings window for "most talked about". */
  trendingDays: 7,
  /** CIRCL "exploited" sightings window. */
  exploitedSightingDays: 30,
};

export const LIMITS = {
  now: 40,
  soon: 20,
  watch: 20,
  trending: 12,
  breaches: 6,
  news: 12,
  /** CVE records fetched per radar build (GitHub raw), to enrich items with SSVC and fixed versions. */
  cveRecords: 90,
};
