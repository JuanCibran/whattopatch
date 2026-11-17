import type { MetadataRoute } from "next";
import { SITE } from "@/lib/config";
import { getRadar, getRecentKevIds } from "@/lib/radar";

export default async function sitemap(): Promise<MetadataRoute.Sitemap> {
  const [radar, kevIds] = await Promise.all([getRadar(), getRecentKevIds(200)]);
  const ids = new Set<string>(kevIds);
  for (const i of [...radar.now, ...radar.soon, ...radar.watch]) if (i.cve) ids.add(i.cve);
  return [
    { url: SITE.url, lastModified: radar.generatedAt, changeFrequency: "hourly", priority: 1 },
    ...[...ids].map((id) => ({
      url: `${SITE.url}/cve/${id}`,
      changeFrequency: "daily" as const,
      priority: 0.6,
    })),
  ];
}
