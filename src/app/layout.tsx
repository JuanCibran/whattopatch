import type { Metadata, Viewport } from "next";
import localFont from "next/font/local";
import Link from "next/link";
import { Wordmark } from "@/components/Wordmark";
import { SITE } from "@/lib/config";
import "./globals.css";

const bigShoulders = localFont({
  src: "./fonts/BigShoulders-latin-var.woff2",
  variable: "--font-big-shoulders",
  weight: "100 900",
  display: "swap",
});

const atkinson = localFont({
  src: "./fonts/AtkinsonHyperlegibleNext-latin-var.woff2",
  variable: "--font-atkinson",
  weight: "200 800",
  display: "swap",
});

export const metadata: Metadata = {
  metadataBase: new URL(SITE.url),
  title: {
    default: `${SITE.name}: what attackers are exploiting now, and what to do`,
    template: `%s | ${SITE.name}`,
  },
  description:
    "A triage board for vulnerabilities. See what's being exploited right now, check whether it hits the products you run, and get plain-language steps to fix it.",
  alternates: {
    types: { "application/rss+xml": `${SITE.url}/feed.xml` },
  },
  openGraph: {
    siteName: SITE.name,
    type: "website",
  },
};

export const viewport: Viewport = {
  themeColor: "#edf1f5",
};

export default function RootLayout({ children }: LayoutProps<"/">) {
  return (
    <html lang="en" className={`${bigShoulders.variable} ${atkinson.variable}`}>
      <body className="min-h-dvh antialiased">
        <a
          href="#main"
          className="sr-only focus:not-sr-only focus:absolute focus:left-4 focus:top-4 focus:z-50 focus:rounded focus:bg-sheet focus:px-3 focus:py-2"
        >
          Skip to content
        </a>
        <header className="mx-auto flex max-w-[1180px] flex-wrap items-center justify-between gap-x-6 gap-y-2 px-5 pt-5 sm:px-8">
          <Link href="/" className="text-ink no-underline" aria-label={`${SITE.name} home`}>
            <Wordmark />
          </Link>
          <nav aria-label="Site" className="flex items-center gap-5 text-[0.9375rem]">
            <Link href="/#how-we-rank">How we rank</Link>
            <a href="/feed.xml">RSS</a>
            <a href="/api/v1/radar">API</a>
            {SITE.repo ? <a href={SITE.repo}>Source</a> : null}
          </nav>
        </header>
        <div id="main">{children}</div>
        <footer className="mx-auto mt-20 max-w-[1180px] px-5 pb-12 sm:px-8">
          <div className="rule-top grid gap-6 pt-6 text-sm text-graphite md:grid-cols-[1fr_1fr]">
            <p className="max-w-[62ch]">
              {SITE.name} is an independent project, not affiliated with CISA, FIRST, ENISA, CIRCL, the CVE Program or
              Have I Been Pwned. It ranks public data automatically. Always confirm fixes against your vendor&apos;s
              advisory before you change production systems.
            </p>
            <p className="max-w-[62ch]">
              Data from{" "}
              <a href="https://www.cisa.gov/known-exploited-vulnerabilities-catalog">CISA KEV</a>,{" "}
              <a href="https://www.cve.org/">the CVE Program</a>, <a href="https://www.first.org/epss/">FIRST EPSS</a>,{" "}
              <a href="https://euvd.enisa.europa.eu/">ENISA EUVD</a>,{" "}
              <a href="https://vulnerability.circl.lu/">CIRCL Vulnerability-Lookup</a> and{" "}
              <a href="https://haveibeenpwned.com/">Have I Been Pwned</a> (breach data under CC BY 4.0). Headlines link to
              their publishers.
            </p>
          </div>
        </footer>
      </body>
    </html>
  );
}
