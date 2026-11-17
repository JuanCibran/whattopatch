import type { Metadata } from "next";
import Link from "next/link";
import { notFound } from "next/navigation";
import { Suspense } from "react";
import { fmtDate, fmtPercentile, fmtProbability, productName } from "@/lib/format";
import { getCveDetail, getRecentKevIds } from "@/lib/radar";
import { TIER_LABEL } from "@/lib/triage";
import type { RadarItem } from "@/lib/types";

const CVE_RE = /^CVE-\d{4}-\d{4,}$/;

export async function generateStaticParams() {
  const ids = await getRecentKevIds(12);
  return (ids.length ? ids : ["CVE-2024-3400"]).map((id) => ({ id }));
}

export async function generateMetadata({ params }: PageProps<"/cve/[id]">): Promise<Metadata> {
  const { id } = await params;
  const cve = decodeURIComponent(id).toUpperCase();
  return {
    title: `${cve}: is it exploited, and what to do`,
    description: `Exploitation status, fixed versions and step-by-step guidance for ${cve}.`,
    alternates: { canonical: `/cve/${cve}` },
  };
}

export default function CvePage(props: PageProps<"/cve/[id]">) {
  return (
    <main className="mx-auto max-w-[1180px] px-5 sm:px-8">
      <p className="mt-8 text-[0.9375rem]">
        <Link href="/">Back to all vulnerabilities</Link>
      </p>
      <Suspense fallback={<DetailSkeleton />}>
        <Detail params={props.params} />
      </Suspense>
    </main>
  );
}

const STATUS_LINE: Record<RadarItem["tier"], string> = {
  now: "Exploited in the wild",
  soon: "Likely to be exploited soon",
  watch: "No attacks reported yet",
};

async function Detail({ params }: { params: PageProps<"/cve/[id]">["params"] }) {
  const { id } = await params;
  const cve = decodeURIComponent(id).toUpperCase();
  if (!CVE_RE.test(cve)) notFound();
  const { item, record, kev, statuses, asOf } = await getCveDetail(cve);

  if (!item) {
    const unreachable = statuses.filter((s) => !s.ok);
    return (
      <section className="mt-8 max-w-[68ch]">
        <h1 className="display text-[clamp(2.75rem,8vw,5rem)]">{cve}</h1>
        <p className="mt-4 text-[1.1875rem]">
          {unreachable.length === statuses.length
            ? "The CVE record couldn't be loaded right now. Try again in a couple of minutes."
            : "There's no published CVE record with this ID yet. It may be reserved but not disclosed, or the ID may have a typo."}
        </p>
        <p className="mt-4">
          <a href={`https://www.cve.org/CVERecord?id=${cve}`}>Look it up on CVE.org</a>
        </p>
      </section>
    );
  }

  const fixedRows = record?.affected.filter((a) => a.ranges.length || a.fixed.length) ?? [];
  const otherRefs = record?.references ?? [];

  return (
    <article className={`tier-${item.tier} mt-6`}>
      <header className="grid grid-cols-[12px_minmax(0,1fr)] gap-x-5">
        <div className="rounded-sm bg-[var(--tier)]" aria-hidden="true" />
        <div>
          <p className="font-bold text-graphite">
            {TIER_LABEL[item.tier]}: {STATUS_LINE[item.tier]}
          </p>
          <h1 className="display mt-1 text-[clamp(2.75rem,8vw,5.25rem)]">{item.id}</h1>
          <p className="mt-2 text-[1.1875rem] font-bold leading-snug">
            {productName(item.vendor, item.product)}
          </p>
          <p className="mt-1 max-w-[70ch] text-[1.125rem]">{item.title}</p>
        </div>
      </header>

      <div className="mt-10 grid gap-12 lg:grid-cols-[minmax(0,1fr)_320px]">
        <div className="min-w-0">
          <section aria-labelledby="h-todo">
            <h2 id="h-todo" className="section-title">
              What to do
            </h2>
            <p className="mt-2 max-w-[66ch] text-[1.125rem]">{item.advice.why}</p>
            <ol className="steps mt-4 max-w-[66ch]">
              {item.advice.steps.map((step) => (
                <li key={step.title}>
                  <div>
                    <p className="text-[1.0625rem] font-bold">{step.title}</p>
                    <p className="text-graphite">
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
          </section>

          {fixedRows.length ? (
            <section className="mt-12" aria-labelledby="h-versions">
              <h2 id="h-versions" className="section-title">
                Affected and fixed versions
              </h2>
              <p className="mt-1 text-graphite">From the official CVE record. Confirm against the vendor advisory before upgrading.</p>
              <div className="mt-4 overflow-x-auto">
                <table className="w-full min-w-[520px] border-collapse text-left text-[0.9688rem]">
                  <thead>
                    <tr className="border-b border-rule">
                      <th scope="col" className="py-2 pr-4">Product</th>
                      <th scope="col" className="py-2 pr-4">Affected</th>
                      <th scope="col" className="py-2">Fixed in</th>
                    </tr>
                  </thead>
                  <tbody>
                    {fixedRows.map((a) => (
                      <tr key={`${a.vendor}-${a.product}`} className="border-b border-rule align-top">
                        <th scope="row" className="whitespace-nowrap py-2 pr-4 font-bold">
                          {a.product}
                        </th>
                        <td className="py-2 pr-4">{a.ranges.join("; ") || "See advisory"}</td>
                        <td className="py-2">{a.fixed.join(", ") || "See advisory"}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </section>
          ) : null}

          {record && (record.solutions.length || record.workarounds.length) ? (
            <section className="mt-12" aria-labelledby="h-vendor">
              <h2 id="h-vendor" className="section-title">
                Vendor guidance
              </h2>
              <p className="mt-1 text-graphite">Quoted from the CVE record. Check the advisory for updates.</p>
              {record.solutions.map((s, i) => (
                <blockquote key={`s${i}`} className="mt-4 max-w-[70ch] whitespace-pre-line border-l-4 border-rule pl-4">
                  {s}
                </blockquote>
              ))}
              {record.workarounds.length ? (
                <>
                  <h3 className="mt-6 font-bold">Workarounds</h3>
                  {record.workarounds.map((w, i) => (
                    <blockquote key={`w${i}`} className="mt-2 max-w-[70ch] whitespace-pre-line border-l-4 border-rule pl-4">
                      {w}
                    </blockquote>
                  ))}
                </>
              ) : null}
            </section>
          ) : null}

          <section className="mt-12" aria-labelledby="h-what">
            <h2 id="h-what" className="section-title">
              What it is
            </h2>
            <p className="mt-3 max-w-[70ch] whitespace-pre-line">
              {record?.description || kev?.description || "No description published yet."}
            </p>
          </section>

          {otherRefs.length ? (
            <section className="mt-12" aria-labelledby="h-refs">
              <h2 id="h-refs" className="section-title">
                References
              </h2>
              <ul className="mt-3 grid gap-2">
                {otherRefs.map((r) => (
                  <li key={r.url} className="break-words">
                    <a href={r.url} rel="noopener noreferrer" target="_blank">
                      {r.name ?? r.url}
                    </a>
                    {r.tags.includes("vendor-advisory") ? <span className="text-graphite"> (vendor advisory)</span> : null}
                    {r.tags.includes("patch") ? <span className="text-graphite"> (patch)</span> : null}
                  </li>
                ))}
              </ul>
            </section>
          ) : null}
        </div>

        <aside aria-label="Key facts">
          <dl className="grid gap-4 rounded-[10px] border border-rule bg-sheet p-5">
            <Fact label="CISA exploited list">
              {kev ? (
                <>
                  Listed {fmtDate(kev.added, asOf)}
                  {kev.due ? `, federal deadline ${fmtDate(kev.due, asOf)}` : ""}
                  {kev.ransomware ? ". Used in ransomware campaigns" : ""}
                  {kev.forensic ? ". CISA requires a check for compromise" : ""}.
                </>
              ) : item.kev ? (
                `Listed ${fmtDate(item.kev.added, asOf)}`
              ) : (
                "Not listed"
              )}
            </Fact>
            <Fact label="Exploit odds, next 30 days">
              {item.epss
                ? `${fmtProbability(item.epss.score)}, higher than ${fmtPercentile(item.epss.percentile)} of all CVEs`
                : "No score yet"}
            </Fact>
            <Fact label="Severity">
              {item.cvss
                ? `${item.cvss.score.toFixed(1)}${item.cvss.severity ? ` ${item.cvss.severity.toLowerCase()}` : ""} (CVSS ${item.cvss.version ?? ""})`
                : "Not scored"}
            </Fact>
            {item.ssvc ? (
              <Fact label="CISA's analysis">
                {[
                  item.ssvc.exploitation ? `exploitation: ${item.ssvc.exploitation === "poc" ? "public exploit code" : item.ssvc.exploitation}` : null,
                  item.ssvc.automatable ? `automatable: ${item.ssvc.automatable}` : null,
                  item.ssvc.impact ? `impact: ${item.ssvc.impact}` : null,
                ]
                  .filter(Boolean)
                  .join(", ")}
              </Fact>
            ) : null}
            {record?.published ? <Fact label="Published">{fmtDate(record.published, asOf)}</Fact> : null}
            <Fact label="Look it up elsewhere">
              <span className="flex flex-col">
                <a href={`https://www.cve.org/CVERecord?id=${item.id}`}>CVE.org</a>
                <a href={`https://nvd.nist.gov/vuln/detail/${item.id}`}>NIST NVD</a>
                <a href={`https://vulnerability.circl.lu/vuln/${item.id}`}>CIRCL Vulnerability-Lookup</a>
                <a href="https://euvd.enisa.europa.eu/">ENISA EUVD</a>
                {kev ? <a href={`https://www.cisa.gov/known-exploited-vulnerabilities-catalog?field_cve=${item.id}`}>CISA KEV</a> : null}
              </span>
            </Fact>
          </dl>
        </aside>
      </div>
    </article>
  );
}

function Fact({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div>
      <dt className="text-[0.875rem] text-graphite">{label}</dt>
      <dd className="font-bold leading-snug">{children}</dd>
    </div>
  );
}

function DetailSkeleton() {
  return (
    <div className="mt-6 animate-pulse motion-reduce:animate-none" aria-label="Loading vulnerability details">
      <div className="h-5 w-48 rounded bg-rule/70" />
      <div className="mt-3 h-16 w-80 max-w-full rounded bg-rule/70" />
      <div className="mt-4 h-5 w-96 max-w-full rounded bg-rule/70" />
      <div className="mt-10 h-40 max-w-[66ch] rounded bg-rule/50" />
    </div>
  );
}
