import { cacheLife } from "next/cache";
import { LIFE, WINDOWS } from "../config";
import { getJson } from "../http";
import { parseMostSighted, type Sighting } from "../parsers/circl";
import type { SourceResult } from "../types";
import { fail, ok } from "./result";

export type { Sighting } from "../parsers/circl";

const CIRCL_API = "https://vulnerability.circl.lu/api";

function isoDay(offsetDays: number): string {
  return new Date(Date.now() - offsetDays * 86_400_000).toISOString().slice(0, 10);
}

/**
 * CIRCL Vulnerability-Lookup sightings: how often a vulnerability was seen in the wild
 * (social posts, exploit repos, detection feeds). `exploited` counts sightings typed as
 * "exploited", which can show attacks before CISA lists them.
 */
export async function getSightings(): Promise<SourceResult<{ trending: Sighting[]; exploited: Sighting[] }>> {
  "use cache";
  try {
    const [trending, exploited] = await Promise.all([
      getJson(
        `${CIRCL_API}/stats/vulnerability/most_sighted?date_from=${isoDay(WINDOWS.trendingDays)}&limit=40`,
        { timeoutMs: 15_000 },
      ).then(parseMostSighted),
      getJson(
        `${CIRCL_API}/stats/vulnerability/most_sighted?date_from=${isoDay(WINDOWS.exploitedSightingDays)}&sighting_type=exploited&limit=40`,
        { timeoutMs: 15_000 },
      )
        .then(parseMostSighted)
        .catch(() => [] as Sighting[]),
    ]);
    cacheLife(LIFE.radar);
    return ok("circl", { trending, exploited }, { count: trending.length });
  } catch (err) {
    cacheLife(LIFE.retry);
    return fail("circl", err);
  }
}
