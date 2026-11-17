import { cacheLife } from "next/cache";
import { LIFE, LIMITS } from "../config";
import { getJson } from "../http";
import { parseBreaches } from "../parsers/hibp";
import type { Breach, SourceResult } from "../types";
import { fail, ok } from "./result";

const HIBP_API = "https://haveibeenpwned.com/api/v3";

/** Newest breaches added to Have I Been Pwned. Data is CC BY 4.0: the UI credits and links HIBP. */
export async function getBreaches(): Promise<SourceResult<Breach[]>> {
  "use cache";
  try {
    let breaches: Breach[];
    try {
      breaches = parseBreaches(await getJson(`${HIBP_API}/breaches`, { timeoutMs: 15_000 }));
    } catch {
      breaches = parseBreaches(await getJson(`${HIBP_API}/latestbreach`, { timeoutMs: 10_000 }));
    }
    const recent = breaches.slice(0, LIMITS.breaches);
    cacheLife(LIFE.slow);
    return ok("hibp", recent, { count: recent.length, sourceUpdatedAt: recent[0]?.addedDate ?? undefined });
  } catch (err) {
    cacheLife(LIFE.retry);
    return fail("hibp", err);
  }
}
