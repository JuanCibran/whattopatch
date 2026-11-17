import { cacheLife, cacheTag } from "next/cache";
import { LIFE } from "../config";
import { getJson } from "../http";
import type { SourceResult } from "../types";
import { fail, ok } from "./result";
import { parseKev, type KevCatalog } from "../parsers/kev";

export type { KevCatalog, KevEntry } from "../parsers/kev";

/**
 * CISA Known Exploited Vulnerabilities catalog.
 * The GitHub repository is CISA's official mirror of the cisa.gov feed; we try it first because
 * it is fast and reliable from serverless platforms, and fall back to cisa.gov.
 */
export const KEV_URLS = [
  "https://raw.githubusercontent.com/cisagov/kev-data/main/known_exploited_vulnerabilities.json",
  "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
];

export async function getKev(): Promise<SourceResult<KevCatalog>> {
  "use cache";
  cacheTag("kev");
  let lastError: unknown = new Error("no KEV source configured");
  for (const url of KEV_URLS) {
    try {
      const catalog = parseKev(await getJson(url, { timeoutMs: 15_000 }));
      cacheLife(LIFE.radar);
      return ok("kev", catalog, { count: catalog.count, sourceUpdatedAt: catalog.released || undefined });
    } catch (err) {
      lastError = err;
    }
  }
  cacheLife(LIFE.retry);
  return fail("kev", lastError);
}
