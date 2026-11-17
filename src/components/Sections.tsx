import { fmtClock, fmtCount, fmtDate, fmtLongDate } from "@/lib/format";
import type { Radar, SourceStatus } from "@/lib/types";
import { ItemTag } from "./ItemTag";

const container = "mx-auto max-w-[1180px] px-5 sm:px-8";

export function Hero({ radar }: { radar: Radar }) {
  const { top, counts, generatedAt, statuses } = radar;
  const working = statuses.filter((s) => s.ok).length;
  return (
    <section className={`${container} pt-10 sm:pt-14`} aria-labelledby="h-first">
      <p className="text-graphite">{fmtLongDate(generatedAt)}</p>
      <h1 id="h-first" className="display mt-1 text-[clamp(3.75rem,12vw,8rem)]">
        Fix this first
      </h1>
      {top ? (
        <>
          <p className="mt-4 max-w-[58ch] text-[1.1875rem] leading-relaxed">{top.advice.why}</p>
          <div className="mt-6 max-w-[880px]">
            <ItemTag item={top} asOf={generatedAt} variant="hero" open />
          </div>
        </>
      ) : (
        <p className="mt-4 max-w-[58ch] text-[1.1875rem]">
          The exploited-vulnerability feeds couldn&apos;t be reached on this update. The page tries again within a couple of
          minutes.
        </p>
      )}
      <p className="mt-6 max-w-[80ch] text-[0.9375rem] text-graphite">
        {counts.kevTotal ? (
          <>
            CISA added <strong className="text-ink">{counts.kevLast7}</strong> vulnerabilities to its exploited list in the last
            7 days and <strong className="text-ink">{counts.kevLast30}</strong> in the last 30
            {counts.ransomwareLast30 ? (
              <>
                , <strong className="text-ink">{counts.ransomwareLast30}</strong> of them used by ransomware gangs
              </>
            ) : null}
            .{" "}
          </>
        ) : null}
        Updated {fmtClock(generatedAt)} from {working} of {statuses.length} sources.{" "}
        <a href="#how-we-rank">See sources</a>
      </p>
    </section>
  );
}

export function Breaches({ radar }: { radar: Radar }) {
  if (!radar.breaches.length) return null;
  return (
    <section className={`${container} mt-6`} aria-labelledby="h-breaches">
      <div className="rule-top pt-10">
        <h2 id="h-breaches" className="section-title">
          Recent breaches
        </h2>
        <p className="mt-1 max-w-[70ch] text-graphite">
          Newly added to Have I Been Pwned. If you had an account with one of these, change that password everywhere you
          reused it and turn on two-factor authentication.{" "}
          <a href="https://haveibeenpwned.com/">Check your email address</a>
        </p>
        <ul className="mt-5 grid gap-3 md:grid-cols-2">
          {radar.breaches.map((b) => (
            <li key={b.name} className="rounded-[10px] border border-rule bg-sheet p-4">
              <p className="font-bold leading-snug">
                {b.title}
                {b.domain ? <span className="font-normal text-graphite"> ({b.domain})</span> : null}
              </p>
              <p className="mt-0.5 text-[0.9375rem] text-graphite">
                {fmtCount(b.pwnCount)} accounts{b.breachDate ? `, breached ${fmtDate(b.breachDate, radar.generatedAt)}` : ""}
                {b.addedDate ? `, added ${fmtDate(b.addedDate, radar.generatedAt)}` : ""}
                {b.verified ? "" : ", unverified"}
              </p>
              {b.dataClasses.length ? (
                <p className="mt-2 text-[0.9375rem]">
                  <span className="font-bold">Exposed:</span> {b.dataClasses.slice(0, 5).join(", ").toLowerCase()}
                </p>
              ) : null}
            </li>
          ))}
        </ul>
        <p className="mt-3 text-sm text-graphite">
          Breach data from <a href="https://haveibeenpwned.com/">Have I Been Pwned</a>, licensed CC BY 4.0.
        </p>
      </div>
    </section>
  );
}

export function News({ radar }: { radar: Radar }) {
  if (!radar.news.length) return null;
  return (
    <section className={`${container} mt-14`} aria-labelledby="h-news">
      <div className="rule-top pt-10">
        <h2 id="h-news" className="section-title">
          Security news
        </h2>
        <p className="mt-1 max-w-[70ch] text-graphite">
          Latest headlines from security newsrooms. They add context; they don&apos;t change the ranking above.
        </p>
        <ul className="mt-5 grid gap-x-10 gap-y-4 md:grid-cols-2">
          {radar.news.map((n) => (
            <li key={n.url}>
              <a href={n.url} rel="noopener noreferrer" target="_blank" className="font-bold leading-snug">
                {n.title}
              </a>
              <p className="text-[0.875rem] text-graphite">
                {n.source}
                {n.published ? `, ${fmtDate(n.published, radar.generatedAt)}` : ""}
              </p>
            </li>
          ))}
        </ul>
      </div>
    </section>
  );
}

const SOURCE_ROLE: Record<SourceStatus["id"], { role: string; href: string }> = {
  kev: { role: "Vulnerabilities attackers are exploiting, with CISA's deadlines and ransomware flags.", href: "https://www.cisa.gov/known-exploited-vulnerabilities-catalog" },
  cve: { role: "The official record for each CVE: affected and fixed versions, vendor guidance, CISA's exploitation analysis.", href: "https://www.cve.org/" },
  epss: { role: "Probability that a vulnerability is exploited in the next 30 days, updated daily.", href: "https://www.first.org/epss/" },
  euvd: { role: "New critical vulnerabilities and ENISA's exploited list.", href: "https://euvd.enisa.europa.eu/" },
  circl: { role: "Sightings: how often a vulnerability shows up in posts, exploit code and detections.", href: "https://vulnerability.circl.lu/" },
  hibp: { role: "Newly loaded data breaches.", href: "https://haveibeenpwned.com/" },
  news: { role: "Headlines from BleepingComputer, The Hacker News, SecurityWeek and Krebs on Security.", href: "#h-news" },
};

export function HowWeRank({ radar }: { radar: Radar }) {
  return (
    <section id="how-we-rank" className={`${container} mt-14 scroll-mt-6`} aria-labelledby="h-method">
      <div className="rule-top pt-10">
        <h2 id="h-method" className="section-title">
          How we rank
        </h2>
        <div className="mt-5 grid gap-10 lg:grid-cols-2">
          <div className="max-w-[66ch] space-y-4">
            <p>
              <strong className="text-now">Now</strong> means there is evidence of attacks: the vulnerability is on CISA&apos;s
              Known Exploited Vulnerabilities list, ENISA lists it as exploited, security teams have reported exploitation on
              CIRCL, or CISA&apos;s analysis of the CVE record marks exploitation as active.
            </p>
            <p>
              <strong className="text-[#9a7400]">This week</strong> means no confirmed attacks yet, but FIRST&apos;s EPSS model
              gives it at least a 10% chance of exploitation in the next 30 days, or exploit code is public and the attack can be
              automated.
            </p>
            <p>
              <strong className="text-watch">Watch</strong> means critical severity (CVSS 9 or higher), published in the last
              week, with low exploit odds.
            </p>
            <p>
              Within each list, items are ordered by evidence of exploitation, ransomware use, CISA&apos;s forensic-triage flag,
              exploit odds, severity, how recent it is, and whether it&apos;s an internet-facing device like a firewall or VPN.
            </p>
            <p className="text-graphite">
              Two limits to keep in mind. Your stack is matched by product name, not version, so check the fixed versions on
              each vulnerability&apos;s page. And exploit odds are a statistical model, not a promise. We don&apos;t rank on
              NIST&apos;s NVD because its analysis backlog leaves many recent CVEs unscored there; we read the CVE records and
              CISA&apos;s own analysis directly.
            </p>
          </div>
          <div>
            <h3 className="font-bold">Sources on this update</h3>
            <ul className="mt-3 grid gap-3">
              {radar.statuses.map((s) => (
                <li key={s.id} className="grid grid-cols-[1.25rem_minmax(0,1fr)] gap-2 text-[0.9375rem]">
                  <span
                    aria-hidden="true"
                    className={`mt-1.5 size-2.5 rounded-full ${s.ok ? "bg-watch" : "bg-now"}`}
                  />
                  <div>
                    <p>
                      <a href={SOURCE_ROLE[s.id].href} className="font-bold">
                        {s.name}
                      </a>
                      <span className="text-graphite">
                        {s.ok ? ", working" : `, unreachable: ${s.error ?? "unknown error"}`}
                        {s.ok && s.id === "kev" && s.sourceUpdatedAt ? `, catalog released ${fmtDate(s.sourceUpdatedAt, radar.generatedAt)} ${fmtClock(s.sourceUpdatedAt)}` : ""}
                        {s.ok && s.id === "epss" && s.sourceUpdatedAt ? `, model of ${fmtDate(s.sourceUpdatedAt, radar.generatedAt)}` : ""}
                      </span>
                    </p>
                    <p className="text-graphite">{SOURCE_ROLE[s.id].role}</p>
                  </div>
                </li>
              ))}
            </ul>
          </div>
        </div>
      </div>
    </section>
  );
}
