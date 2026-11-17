import { SITE } from "@/lib/config";
import { getRadar } from "@/lib/radar";
import { TIER_LABEL } from "@/lib/triage";
import { productName } from "@/lib/format";

function esc(text: string): string {
  return text
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&apos;");
}

/** RSS of everything in Now and This week, with the first steps of "What to do". */
export async function GET() {
  const radar = await getRadar();
  const items = [...radar.now, ...radar.soon].filter((i) => i.cve);
  const entries = items
    .map((i) => {
      const name = productName(i.vendor, i.product);
      const steps = i.advice.steps.map((s, n) => `${n + 1}. ${s.title}: ${s.detail}`).join("\n");
      const date = new Date(i.kev?.added || i.published || radar.generatedAt).toUTCString();
      return `    <item>
      <title>${esc(`[${TIER_LABEL[i.tier]}] ${name ? `${name}: ` : ""}${i.title} (${i.cve})`)}</title>
      <link>${SITE.url}/cve/${i.cve}</link>
      <guid isPermaLink="false">${esc(`${i.cve}-${i.tier}`)}</guid>
      <pubDate>${date}</pubDate>
      <description>${esc(`${i.advice.why}\n\n${steps}`)}</description>
    </item>`;
    })
    .join("\n");

  const xml = `<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0" xmlns:atom="http://www.w3.org/2005/Atom">
  <channel>
    <title>${esc(SITE.name)}</title>
    <link>${SITE.url}</link>
    <description>${esc(SITE.tagline)}</description>
    <language>en</language>
    <lastBuildDate>${new Date(radar.generatedAt).toUTCString()}</lastBuildDate>
    <atom:link href="${SITE.url}/feed.xml" rel="self" type="application/rss+xml" />
${entries}
  </channel>
</rss>`;

  return new Response(xml, {
    headers: { "content-type": "application/rss+xml; charset=utf-8" },
  });
}
