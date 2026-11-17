import { cacheLife } from "next/cache";
import { LIFE, LIMITS } from "../config";
import { getText } from "../http";
import { mergeNews, parseFeed } from "../parsers/news";
import type { NewsItem, SourceResult } from "../types";
import { fail, ok } from "./result";

export const NEWS_FEEDS = [
  { name: "BleepingComputer", url: "https://www.bleepingcomputer.com/feed/" },
  { name: "The Hacker News", url: "https://thehackernews.com/feeds/posts/default" },
  { name: "SecurityWeek", url: "https://www.securityweek.com/feed" },
  { name: "Krebs on Security", url: "https://krebsonsecurity.com/feed/" },
];

/** Headlines only: context for the radar, never an input to the ranking. */
export async function getNews(): Promise<SourceResult<NewsItem[]>> {
  "use cache";
  const results = await Promise.allSettled(
    NEWS_FEEDS.map(async (f) => parseFeed(await getText(f.url, { timeoutMs: 10_000 }), f.name)),
  );
  const lists = results.flatMap((r) => (r.status === "fulfilled" ? [r.value] : []));
  if (!lists.length) {
    cacheLife(LIFE.retry);
    const firstError = results.find((r) => r.status === "rejected") as PromiseRejectedResult | undefined;
    return fail("news", firstError?.reason ?? new Error("no feed answered"));
  }
  const items = mergeNews(lists, LIMITS.news);
  cacheLife(LIFE.radar);
  return ok("news", items, { count: items.length });
}
