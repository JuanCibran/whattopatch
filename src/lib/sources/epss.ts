import { cacheLife } from "next/cache";
import { LIFE } from "../config";
import { getJson } from "../http";
import { chunk, parseEpss } from "../parsers/epss";
import { CVE_ID_RE } from "../parsers/util";
import type { Epss, SourceResult } from "../types";
import { fail, ok } from "./result";

const EPSS_API = "https://api.first.org/data/v1/epss";

/** Scores for a set of CVEs. Normalizes the list first so equal sets share one cache entry. */
export async function getEpss(cves: string[]): Promise<SourceResult<Record<string, Epss>>> {
  const ids = [...new Set(cves.map((c) => c.toUpperCase()).filter((c) => CVE_ID_RE.test(c)))].sort();
  if (!ids.length) return ok("epss", {}, { count: 0 });
  return fetchEpss(ids);
}

async function fetchEpss(ids: string[]): Promise<SourceResult<Record<string, Epss>>> {
  "use cache";
  try {
    const parts = await Promise.all(
      chunk(ids, 50).map((group) =>
        getJson(`${EPSS_API}?cve=${group.join(",")}&limit=${group.length}`, { cacheSeconds: 21_600 }).then(parseEpss),
      ),
    );
    const scores = Object.assign({}, ...parts) as Record<string, Epss>;
    const modelDate = Object.values(scores)[0]?.date;
    cacheLife(LIFE.daily);
    return ok("epss", scores, { count: Object.keys(scores).length, sourceUpdatedAt: modelDate || undefined });
  } catch (err) {
    cacheLife(LIFE.retry);
    return fail("epss", err);
  }
}
