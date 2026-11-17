import Link from "next/link";
import { fmtDate, fmtProbability, productName } from "@/lib/format";
import { daysBetween } from "@/lib/parsers/util";
import type { RadarItem } from "@/lib/types";

type Props = {
  item: RadarItem;
  asOf: string;
  mine?: boolean;
  variant?: "list" | "hero";
  open?: boolean;
};

export function itemHref(item: RadarItem): string | null {
  return item.cve ? `/cve/${item.cve}` : null;
}

export function ItemTag({ item, asOf, mine = false, variant = "list", open = false }: Props) {
  const href = itemHref(item);
  const isHero = variant === "hero";
  const isNew = item.kev ? daysBetween(item.kev.added, asOf) <= 2 : false;
  const vendorLine = productName(item.vendor, item.product);
  const TitleTag = isHero ? "h2" : "h3";

  return (
    <article
      className={`tag tier-${item.tier} ${mine ? "is-mine" : ""} ${isHero ? "hero-tag" : ""}`}
      aria-labelledby={`t-${item.id}`}
    >
      <div className="tag-strip" aria-hidden="true" />
      <div className={`tag-body ${isHero ? "sm:px-7 sm:py-6" : ""}`}>
        <div className="flex flex-wrap items-start justify-between gap-x-4 gap-y-1">
          <p className={`font-bold text-graphite ${isHero ? "text-base" : "text-[0.9375rem]"}`}>{vendorLine || "Unknown product"}</p>
          <div className="flex flex-wrap gap-1.5">
            {isNew ? <span className="flag flag-new">New</span> : null}
            {mine ? <span className="flag flag-mine">In your stack</span> : null}
            {item.kev?.ransomware ? <span className="flag flag-ransom">Used by ransomware</span> : null}
            {item.kev?.forensic ? <span className="flag flag-now">Check for compromise</span> : null}
          </div>
        </div>

        <TitleTag
          id={`t-${item.id}`}
          className={isHero ? "mt-1 text-[1.375rem] font-bold leading-snug sm:text-[1.625rem]" : "mt-0.5 text-[1.0625rem] font-bold leading-snug"}
        >
          {href ? (
            <Link href={href} className="text-ink no-underline hover:underline">
              {item.title}
            </Link>
          ) : (
            item.title
          )}
        </TitleTag>

        {isHero && item.summary ? <p className="mt-2 hidden max-w-[68ch] text-graphite sm:block">{item.summary}</p> : null}

        <div className="mt-2 flex flex-wrap gap-x-4 gap-y-1">
          <span className="fact">
            {href ? <Link href={href}>{item.id}</Link> : <strong>{item.id}</strong>}
          </span>
          {item.kev?.added ? (
            <span className="fact">
              Listed <strong>{fmtDate(item.kev.added, asOf)}</strong>
            </span>
          ) : item.published ? (
            <span className="fact">
              Published <strong>{fmtDate(item.published, asOf)}</strong>
            </span>
          ) : null}
          {item.kev?.due ? (
            <span className="fact">
              CISA deadline <strong>{fmtDate(item.kev.due, asOf)}</strong>
            </span>
          ) : null}
          {item.epss ? (
            <span className="fact" title="FIRST EPSS: probability of exploitation in the next 30 days">
              Exploit odds <strong>{fmtProbability(item.epss.score)}</strong>
            </span>
          ) : null}
          {item.cvss ? (
            <span className="fact" title={item.cvss.vector ?? undefined}>
              CVSS <strong>{item.cvss.score.toFixed(1)}</strong>
            </span>
          ) : null}
          {item.sightings ? (
            <span className="fact" title="Sightings this week on CIRCL Vulnerability-Lookup">
              Sightings <strong>{item.sightings}</strong>
            </span>
          ) : null}
        </div>

        <details className="todo mt-2" open={open}>
          <summary>What to do</summary>
          {isHero ? null : <p className="mt-1 max-w-[68ch]">{item.advice.why}</p>}
          <ol className="steps max-w-[68ch]">
            {item.advice.steps.map((step) => (
              <li key={step.title}>
                <div>
                  <p className="font-bold leading-snug">{step.title}</p>
                  <p className="text-[0.9688rem] text-graphite">
                    {step.detail}
                    {step.href ? (
                      <>
                        {" "}
                        <a href={step.href} rel="noopener noreferrer" target="_blank">
                          {step.hrefLabel ?? "Details"}
                        </a>
                      </>
                    ) : null}
                  </p>
                </div>
              </li>
            ))}
          </ol>
          {href ? (
            <p className="mt-3 text-[0.9375rem]">
              <Link href={href}>See fixed versions, vendor guidance and references</Link>
            </p>
          ) : null}
        </details>
      </div>
    </article>
  );
}
