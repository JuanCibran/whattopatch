import { SITE } from "@/lib/config";
import { getRadar } from "@/lib/radar";
import type { RadarItem } from "@/lib/types";

function publicItem(item: RadarItem): Omit<RadarItem, "matchText"> {
  const copy: Partial<RadarItem> = { ...item };
  delete copy.matchText;
  return copy as Omit<RadarItem, "matchText">;
}

/** Public JSON API: the current board, ranked, with advice. */
export async function GET() {
  const radar = await getRadar();
  const body = {
    name: SITE.name,
    generatedAt: radar.generatedAt,
    sources: radar.statuses,
    counts: radar.counts,
    top: radar.top ? publicItem(radar.top) : null,
    now: radar.now.map(publicItem),
    thisWeek: radar.soon.map(publicItem),
    watch: radar.watch.map(publicItem),
    attribution:
      "Data: CISA KEV, CVE Program, FIRST EPSS, ENISA EUVD, CIRCL Vulnerability-Lookup. Rankings and advice by WhatToPatch.",
  };
  return Response.json(body, {
    headers: { "access-control-allow-origin": "*" },
  });
}
