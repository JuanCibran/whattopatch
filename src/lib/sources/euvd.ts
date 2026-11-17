import { cacheLife } from "next/cache";
import { LIFE, WINDOWS } from "../config";
import { getJson } from "../http";
import { parseEuvdList, type EuvdItem } from "../parsers/euvd";
import type { SourceResult } from "../types";
import { fail, ok } from "./result";

export type { EuvdItem } from "../parsers/euvd";

const EUVD_API = "https://euvdservices.enisa.europa.eu/api";

function isoDay(offsetDays: number): string {
  return new Date(Date.now() - offsetDays * 86_400_000).toISOString().slice(0, 10);
}

/**
 * Critical vulnerabilities (CVSS 9+) published in the last few days, plus ENISA's latest
 * exploited list. The search endpoint path has changed over time, so we try both known paths
 * and fall back to the convenience endpoint (8 newest).
 */
export async function getEuvd(): Promise<SourceResult<{ critical: EuvdItem[]; exploited: EuvdItem[] }>> {
  "use cache";
  const from = isoDay(WINDOWS.criticalDays);
  const query = `fromScore=9&toScore=10&fromDate=${from}&size=100&page=0`;
  const criticalUrls = [
    `${EUVD_API}/search?${query}`,
    `${EUVD_API}/vulnerabilities?${query}`,
    `${EUVD_API}/criticalvulnerabilities`,
  ];
  try {
    let critical: EuvdItem[] | null = null;
    let lastError: unknown = null;
    for (const url of criticalUrls) {
      try {
        critical = parseEuvdList(await getJson(url, { timeoutMs: 15_000 }));
        break;
      } catch (err) {
        lastError = err;
      }
    }
    if (!critical) throw lastError ?? new Error("EUVD returned nothing");
    let exploited: EuvdItem[] = [];
    try {
      exploited = parseEuvdList(await getJson(`${EUVD_API}/exploitedvulnerabilities`, { timeoutMs: 15_000 }));
    } catch {
      // The exploited list is a bonus; KEV already covers most of it.
    }
    cacheLife(LIFE.radar);
    return ok("euvd", { critical, exploited }, { count: critical.length + exploited.length });
  } catch (err) {
    cacheLife(LIFE.retry);
    return fail("euvd", err);
  }
}
