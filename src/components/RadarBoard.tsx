"use client";

import Link from "next/link";
import { useEffect, useId, useMemo, useState, useSyncExternalStore } from "react";
import { fmtDate } from "@/lib/format";
import { daysBetween } from "@/lib/parsers/util";
import {
  CUSTOM_PREFIX,
  STACK_CATALOG,
  STACK_GROUPS,
  decodeStack,
  entryFor,
  entryMatches,
  matchText,
  type StackEntry,
} from "@/lib/stack";
import { TIER_LABEL } from "@/lib/triage";
import type { RadarItem, Tier, Trending } from "@/lib/types";
import { ItemTag } from "./ItemTag";
import { getServerSnapshot, getSnapshot, shareUrl, subscribe, writeStack } from "./stack-store";

type KevRow = [string, string, string, string, string, 0 | 1];

const TIER_INTRO: Record<Tier, string> = {
  now: "Attackers are exploiting these. Patch today.",
  soon: "Likely to be exploited soon. Patch within seven days.",
  watch: "Critical, but no attacks reported yet. Patch in your normal cycle.",
};

type Props = {
  now: RadarItem[];
  soon: RadarItem[];
  watch: RadarItem[];
  trending: Trending[];
  asOf: string;
};

export function RadarBoard({ now, soon, watch, trending, asOf }: Props) {
  const raw = useSyncExternalStore(subscribe, getSnapshot, getServerSnapshot);
  const stackIds = useMemo(() => decodeStack(raw), [raw]);
  const stack = useMemo(() => stackIds.map(entryFor).filter((e): e is StackEntry => e !== null), [stackIds]);
  const [onlyMine, setOnlyMine] = useState(false);
  const [kevRows, setKevRows] = useState<KevRow[] | null>(null);
  const [kevError, setKevError] = useState(false);
  const hasStack = stack.length > 0;

  useEffect(() => {
    if (!hasStack || kevRows) return;
    let cancelled = false;
    fetch("/api/v1/kev-index")
      .then((r) => (r.ok ? r.json() : Promise.reject(new Error(String(r.status)))))
      .then((data: { rows?: KevRow[] }) => {
        if (!cancelled) setKevRows(Array.isArray(data.rows) ? data.rows : []);
      })
      .catch(() => {
        if (!cancelled) setKevError(true);
      });
    return () => {
      cancelled = true;
    };
  }, [hasStack, kevRows]);

  const mineOf = (item: RadarItem) => hasStack && stack.some((e) => entryMatches(e, item.matchText));
  const tiers: Array<[Tier, RadarItem[]]> = [
    ["now", now],
    ["soon", soon],
    ["watch", watch],
  ];

  return (
    <div className="mx-auto grid max-w-[1180px] gap-12 px-5 sm:px-8 lg:grid-cols-[minmax(0,1fr)_340px]">
      <aside className="order-first lg:order-last" aria-label="Your stack">
        <div className="lg:sticky lg:top-6">
          <StackPanel stack={stack} kevRows={kevRows} kevError={kevError} asOf={asOf} />
          {hasStack ? (
            <label className="mt-4 flex items-center gap-2 text-[0.9375rem] font-bold">
              <input
                type="checkbox"
                className="size-4 accent-[var(--color-ballpoint)]"
                checked={onlyMine}
                onChange={(e) => setOnlyMine(e.target.checked)}
              />
              Show only my stack in the lists
            </label>
          ) : null}
          <TrendingList trending={trending} />
        </div>
      </aside>

      <div className="min-w-0">
        {tiers.map(([tier, items]) => {
          const shown = onlyMine && hasStack ? items.filter(mineOf) : items;
          return (
            <section key={tier} id={tier} aria-labelledby={`h-${tier}`} className={`tier-${tier} mb-14 scroll-mt-6`}>
              <div className="mb-4 flex items-end justify-between gap-4">
                <div>
                  <h2 id={`h-${tier}`} className="section-title flex items-center gap-3">
                    <span aria-hidden="true" className="inline-block h-6 w-2.5 rounded-sm bg-[var(--tier)]" />
                    {TIER_LABEL[tier]}
                  </h2>
                  <p className="mt-1 text-graphite">{TIER_INTRO[tier]}</p>
                </div>
                <p className="display text-[2rem] text-graphite" aria-label={`${shown.length} items`}>
                  {shown.length}
                </p>
              </div>
              {shown.length ? (
                <div className="grid gap-3">
                  {shown.map((item) => (
                    <ItemTag key={item.id} item={item} asOf={asOf} mine={mineOf(item)} />
                  ))}
                </div>
              ) : (
                <p className="rounded-md border border-dashed border-rule bg-sheet px-4 py-5 text-graphite">
                  {onlyMine && hasStack
                    ? `Nothing in your stack is in ${TIER_LABEL[tier]} right now.`
                    : tier === "now"
                      ? "No exploited vulnerabilities could be loaded right now. The page retries in a couple of minutes."
                      : "Nothing here right now. This list fills from ENISA's critical feed and exploit-likelihood scores."}
                </p>
              )}
            </section>
          );
        })}
      </div>
    </div>
  );
}

function StackPanel({
  stack,
  kevRows,
  kevError,
  asOf,
}: {
  stack: StackEntry[];
  kevRows: KevRow[] | null;
  kevError: boolean;
  asOf: string;
}) {
  const inputId = useId();
  const listId = useId();
  const [query, setQuery] = useState("");
  const [copied, setCopied] = useState(false);
  const [showAll, setShowAll] = useState(false);
  const ids = stack.map((e) => e.id);

  const suggestions = useMemo(() => {
    const q = query.trim().toLowerCase();
    if (!q) return [];
    return STACK_CATALOG.filter(
      (e) => !ids.includes(e.id) && (e.label.toLowerCase().includes(q) || e.id.includes(q) || (e.note ?? "").toLowerCase().includes(q)),
    ).slice(0, 8);
  }, [query, ids]);

  const add = (id: string) => {
    if (!ids.includes(id)) writeStack([...ids, id]);
    setQuery("");
  };
  const remove = (id: string) => writeStack(ids.filter((x) => x !== id));
  const customId = `${CUSTOM_PREFIX}${query.trim().toLowerCase()}`;

  const kevMatches = useMemo(() => {
    if (!kevRows || !stack.length) return [];
    return kevRows.filter((r) => stack.some((e) => entryMatches(e, matchText(r[1], r[2], r[3]))));
  }, [kevRows, stack]);
  const recent = kevMatches.filter((r) => daysBetween(r[4], asOf) <= 90).length;
  const ransomware = kevMatches.filter((r) => r[5] === 1).length;
  const oldest = kevMatches.length ? kevMatches[kevMatches.length - 1][4].slice(0, 4) : "";
  const perEntry = (entry: StackEntry) =>
    kevRows ? kevRows.filter((r) => entryMatches(entry, matchText(r[1], r[2], r[3]))).length : null;

  const copyLink = async () => {
    try {
      await navigator.clipboard.writeText(shareUrl(ids));
      setCopied(true);
      setTimeout(() => setCopied(false), 2500);
    } catch {
      window.prompt("Copy this link:", shareUrl(ids));
    }
  };

  return (
    <div className="rounded-[10px] border border-rule bg-sheet p-5">
      <h2 className="section-title text-[1.75rem]">Your stack</h2>
      <p className="mt-1 text-[0.9375rem] text-graphite">
        Pick the products you run. We&apos;ll mark what affects them on this page and list every exploited flaw in them.
        Your list stays in this browser.
      </p>

      <label htmlFor={inputId} className="mt-4 block text-[0.9375rem] font-bold">
        Add a product
      </label>
      <input
        id={inputId}
        type="search"
        autoComplete="off"
        value={query}
        onChange={(e) => setQuery(e.target.value)}
        onKeyDown={(e) => {
          if (e.key === "Enter") {
            e.preventDefault();
            if (suggestions[0]) add(suggestions[0].id);
            else if (query.trim().length >= 2) add(customId);
          }
        }}
        aria-controls={listId}
        placeholder="Fortinet, Exchange, WordPress…"
        className="mt-1 w-full rounded-md border border-rule bg-white px-3 py-2 text-base outline-none focus-visible:border-ballpoint"
      />
      <div id={listId} aria-live="polite">
        {query.trim() ? (
          <ul className="mt-2 grid gap-1">
            {suggestions.map((e) => (
              <li key={e.id}>
                <button type="button" className="w-full rounded-md px-2 py-1.5 text-left hover:bg-paper" onClick={() => add(e.id)}>
                  <span className="font-bold text-ballpoint">Add {e.label}</span>
                  {e.note ? <span className="block text-[0.8125rem] text-graphite">{e.note}</span> : null}
                </button>
              </li>
            ))}
            {query.trim().length >= 2 && !ids.includes(customId) ? (
              <li>
                <button type="button" className="w-full rounded-md px-2 py-1.5 text-left hover:bg-paper" onClick={() => add(customId)}>
                  <span className="font-bold text-ballpoint">Add &ldquo;{query.trim()}&rdquo; as a keyword</span>
                </button>
              </li>
            ) : null}
          </ul>
        ) : null}
      </div>

      <details className="mt-3 text-[0.9375rem]">
        <summary className="cursor-pointer font-bold text-ballpoint">Browse all {STACK_CATALOG.length} products</summary>
        <div className="mt-2 max-h-72 overflow-y-auto pr-1">
          {STACK_GROUPS.map((group) => (
            <fieldset key={group} className="mb-3">
              <legend className="font-bold">{group}</legend>
              {STACK_CATALOG.filter((e) => e.group === group).map((e) => (
                <label key={e.id} className="flex items-center gap-2 py-0.5">
                  <input
                    type="checkbox"
                    className="size-4 accent-[var(--color-ballpoint)]"
                    checked={ids.includes(e.id)}
                    onChange={(ev) => (ev.target.checked ? add(e.id) : remove(e.id))}
                  />
                  {e.label}
                </label>
              ))}
            </fieldset>
          ))}
        </div>
      </details>

      {stack.length ? (
        <>
          <ul className="mt-4 flex flex-wrap gap-2" aria-label="Products in your stack">
            {stack.map((e) => {
              const n = perEntry(e);
              return (
                <li key={e.id} className="inline-flex items-center gap-1 rounded-full border border-ballpoint bg-white py-1 pl-3 pr-1 text-[0.875rem]">
                  <span className="font-bold">{e.label}</span>
                  {n !== null ? <span className="text-graphite">{n}</span> : null}
                  <button
                    type="button"
                    onClick={() => remove(e.id)}
                    className="ml-1 grid size-6 place-items-center rounded-full text-graphite hover:bg-paper hover:text-ink"
                    aria-label={`Remove ${e.label}`}
                  >
                    ×
                  </button>
                </li>
              );
            })}
          </ul>

          <div className="mt-5 rule-top pt-4">
            <h3 className="font-bold">Exploited flaws in your stack</h3>
            {kevError ? (
              <p className="mt-1 text-[0.9375rem] text-graphite">
                The exploited list didn&apos;t load. Reload the page to try again.
              </p>
            ) : !kevRows ? (
              <p className="mt-1 text-[0.9375rem] text-graphite">Checking CISA&apos;s exploited list…</p>
            ) : kevMatches.length ? (
              <>
                <p className="mt-1 text-[0.9375rem]">
                  <strong>{kevMatches.length}</strong> on CISA&apos;s list since {oldest}, <strong>{recent}</strong> in the last
                  90 days{ransomware ? (
                    <>
                      , <strong>{ransomware}</strong> used by ransomware
                    </>
                  ) : null}
                  . Attackers keep using old ones, so make sure each is patched.
                </p>
                <ul className="mt-3 grid gap-2.5">
                  {(showAll ? kevMatches : kevMatches.slice(0, 6)).map((r) => (
                    <li key={r[0]} className="text-[0.9375rem] leading-snug">
                      <Link href={`/cve/${r[0]}`} className="font-bold">
                        {r[0]}
                      </Link>{" "}
                      <span className="text-graphite">
                        listed {fmtDate(r[4], asOf)}
                        {r[5] ? ", ransomware" : ""}
                      </span>
                      <span className="block">{r[3]}</span>
                    </li>
                  ))}
                </ul>
                {kevMatches.length > 6 ? (
                  <button type="button" className="button button-quiet mt-3" onClick={() => setShowAll((v) => !v)}>
                    {showAll ? "Show fewer" : `Show all ${kevMatches.length}`}
                  </button>
                ) : null}
              </>
            ) : (
              <p className="mt-1 text-[0.9375rem] text-graphite">
                None of these products are on CISA&apos;s exploited list. Keep an eye on This week and Watch.
              </p>
            )}
          </div>

          <div className="mt-5 flex flex-wrap gap-2">
            <button type="button" className="button" onClick={copyLink}>
              {copied ? "Link copied" : "Copy link to this list"}
            </button>
            <button type="button" className="button button-quiet" onClick={() => writeStack([])}>
              Clear list
            </button>
          </div>
        </>
      ) : (
        <p className="mt-4 text-[0.9375rem] text-graphite">
          Nothing picked yet. Start with your firewall or VPN: they&apos;re the most attacked devices.
        </p>
      )}
    </div>
  );
}

function TrendingList({ trending }: { trending: Trending[] }) {
  if (!trending.length) return null;
  const max = Math.max(...trending.map((t) => t.count));
  return (
    <section className="mt-8" aria-labelledby="h-trending">
      <h2 id="h-trending" className="section-title text-[1.75rem]">
        Most talked about
      </h2>
      <p className="mt-1 text-[0.9375rem] text-graphite">
        Most sightings this week on{" "}
        <a href="https://vulnerability.circl.lu/">CIRCL&apos;s Vulnerability-Lookup</a>: posts, exploit code and
        detections.
      </p>
      <ol className="mt-3 grid gap-2">
        {trending.map((t) => (
          <li key={t.cve} className={t.tier ? `tier-${t.tier}` : ""}>
            <div className="flex items-baseline justify-between gap-3 text-[0.9375rem]">
              <Link href={`/cve/${t.cve}`} className="font-bold">
                {t.cve}
              </Link>
              <span className="text-graphite">{t.count}</span>
            </div>
            {t.label ? <p className="truncate text-[0.875rem] text-graphite">{t.label}</p> : null}
            <div className="mt-1 h-1.5 rounded-full bg-rule/60" aria-hidden="true">
              <div
                className="h-1.5 rounded-full bg-[var(--tier,var(--color-graphite))]"
                style={{ width: `${Math.max(6, (t.count / max) * 100)}%` }}
              />
            </div>
          </li>
        ))}
      </ol>
    </section>
  );
}
