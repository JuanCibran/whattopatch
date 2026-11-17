import { cacheLife, cacheTag } from "next/cache";
import { LIFE } from "../config";
import { getJson, SourceError } from "../http";
import { cveRecordPath, parseCveRecord, type CveRecord } from "../parsers/cve";
import type { SourceResult } from "../types";
import { fail, ok } from "./result";

export type { CveRecord } from "../parsers/cve";

const CVELIST_RAW = "https://raw.githubusercontent.com/CVEProject/cvelistV5/main";
const CVE_SERVICES = "https://cveawg.mitre.org/api/cve";

/**
 * The official CVE record. The CVE Program publishes every record to GitHub within minutes;
 * the CVE Services API is the fallback.
 */
export async function getCveRecord(id: string): Promise<SourceResult<CveRecord>> {
  "use cache";
  const cve = id.toUpperCase();
  cacheTag(`cve-${cve}`);
  const path = cveRecordPath(cve);
  if (!path) {
    cacheLife(LIFE.daily);
    return fail("cve", new SourceError(`${cve} is not a valid CVE ID`));
  }
  let lastError: unknown = null;
  for (const url of [`${CVELIST_RAW}/${path}`, `${CVE_SERVICES}/${cve}`]) {
    try {
      const record = parseCveRecord(await getJson(url, { timeoutMs: 10_000, cacheSeconds: 21_600 }));
      cacheLife(LIFE.daily);
      return ok("cve", record, { sourceUpdatedAt: record.updated ?? undefined });
    } catch (err) {
      lastError = err;
    }
  }
  cacheLife(LIFE.retry);
  return fail("cve", lastError);
}
