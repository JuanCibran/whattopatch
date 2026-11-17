import { XMLParser } from "fast-xml-parser";
import type { NewsItem } from "../types";
import { decodeEntities, extractCves, str, toIso } from "./util";

const parser = new XMLParser({
  ignoreAttributes: false,
  attributeNamePrefix: "@_",
  textNodeName: "#text",
  htmlEntities: true,
  processEntities: true,
  trimValues: true,
});

function textOf(node: unknown): string {
  if (node == null) return "";
  if (typeof node === "string" || typeof node === "number") return String(node);
  if (Array.isArray(node)) return textOf(node[0]);
  if (typeof node === "object") return textOf((node as Record<string, unknown>)["#text"]);
  return "";
}

function atomLink(link: unknown): string {
  const links = Array.isArray(link) ? link : [link];
  const pick =
    links.find((l) => l && typeof l === "object" && (l as Record<string, unknown>)["@_rel"] === "alternate") ??
    links.find((l) => l && typeof l === "object" && !(l as Record<string, unknown>)["@_rel"]) ??
    links[0];
  if (typeof pick === "string") return pick;
  if (pick && typeof pick === "object") return str((pick as Record<string, unknown>)["@_href"]);
  return "";
}

/** Parses RSS 2.0 or Atom. Keeps only headline, link and date: we link out, we don't republish. */
export function parseFeed(xml: string, source: string): NewsItem[] {
  const doc = parser.parse(xml) as Record<string, unknown>;
  const out: NewsItem[] = [];
  const rss = doc.rss as { channel?: { item?: unknown } } | undefined;
  const feed = doc.feed as { entry?: unknown } | undefined;
  if (rss?.channel) {
    const items = rss.channel.item;
    for (const it of (Array.isArray(items) ? items : items ? [items] : []) as Array<Record<string, unknown>>) {
      push(out, source, textOf(it.title), textOf(it.link) || textOf(it.guid), textOf(it.pubDate) || textOf(it["dc:date"]));
    }
  } else if (feed) {
    const entries = feed.entry;
    for (const e of (Array.isArray(entries) ? entries : entries ? [entries] : []) as Array<Record<string, unknown>>) {
      push(out, source, textOf(e.title), atomLink(e.link), textOf(e.published) || textOf(e.updated));
    }
  } else {
    throw new Error(`${source} feed is neither RSS nor Atom`);
  }
  return out;
}

function push(out: NewsItem[], source: string, rawTitle: string, rawUrl: string, rawDate: string) {
  const title = decodeEntities(rawTitle).replace(/\s+/g, " ").trim();
  const url = rawUrl.trim();
  if (!title || !/^https?:\/\//i.test(url)) return;
  out.push({ title, url, source, published: toIso(rawDate), cves: extractCves(title) });
}

/** Newest first, one entry per URL and per near-identical title. */
export function mergeNews(lists: NewsItem[][], limit: number): NewsItem[] {
  const all = lists.flat().sort((a, b) => (b.published ?? "").localeCompare(a.published ?? ""));
  const seenUrl = new Set<string>();
  const seenTitle = new Set<string>();
  const out: NewsItem[] = [];
  for (const n of all) {
    const key = n.title.toLowerCase().replace(/[^a-z0-9]+/g, " ").trim();
    if (seenUrl.has(n.url) || seenTitle.has(key)) continue;
    seenUrl.add(n.url);
    seenTitle.add(key);
    out.push(n);
    if (out.length >= limit) break;
  }
  return out;
}
