import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { parseMostSighted } from "../src/lib/parsers/circl";
import { cveRecordPath, parseCveRecord } from "../src/lib/parsers/cve";
import { chunk, parseEpss } from "../src/lib/parsers/epss";
import { parseEuvdList } from "../src/lib/parsers/euvd";
import { parseBreaches } from "../src/lib/parsers/hibp";
import { advisoryUrlsFromNotes, parseKev } from "../src/lib/parsers/kev";
import { mergeNews, parseFeed } from "../src/lib/parsers/news";
import { compareVersions, summarizeAffected } from "../src/lib/parsers/versions";
import { decodeEntities, toIso, truncate } from "../src/lib/parsers/util";

const fixture = (name: string) => JSON.parse(readFileSync(join(__dirname, "fixtures", name), "utf8"));

describe("CISA KEV", () => {
  const catalog = parseKev(fixture("kev-sample.json"));

  it("parses real catalog entries, newest first", () => {
    expect(catalog.count).toBe(152);
    expect(catalog.version).toMatch(/^\d{4}\.\d{2}\.\d{2}$/);
    const dates = catalog.entries.map((e) => e.added);
    expect([...dates].sort().reverse()).toEqual(dates);
  });

  it("reads the BOD 26-04 forensic triage and ransomware flags", () => {
    expect(catalog.entries.some((e) => e.forensic)).toBe(true);
    expect(catalog.entries.every((e) => typeof e.ransomware === "boolean")).toBe(true);
  });

  it("keeps vendor links and drops CISA directives and NVD", () => {
    const urls = advisoryUrlsFromNotes(
      "https://forums.unrealircd.org/viewtopic.php?t=9487 ; BOD 26-04: https://www.cisa.gov/news-events/directives/bod-26-04 ; https://nvd.nist.gov/vuln/detail/CVE-2026-114713",
    );
    expect(urls).toEqual(["https://forums.unrealircd.org/viewtopic.php?t=9487"]);
  });

  it("rejects a feed without vulnerabilities", () => {
    expect(() => parseKev({ title: "nope" })).toThrow();
  });
});

describe("CVE records", () => {
  it("maps IDs to the cvelistV5 layout", () => {
    expect(cveRecordPath("CVE-2024-3400")).toBe("cves/2024/3xxx/CVE-2024-3400.json");
    expect(cveRecordPath("cve-2021-44228")).toBe("cves/2021/44xxx/CVE-2021-44228.json");
    expect(cveRecordPath("CVE-2026-114713")).toBe("cves/2026/114xxx/CVE-2026-114713.json");
    expect(cveRecordPath("CVE-2024-0012")).toBe("cves/2024/0xxx/CVE-2024-0012.json");
    expect(cveRecordPath("not-a-cve")).toBeNull();
  });

  it("extracts severity, SSVC, KEV date, fixes and vendor advisory (PAN-OS)", () => {
    const r = parseCveRecord(fixture("CVE-2024-3400.json"));
    expect(r.id).toBe("CVE-2024-3400");
    expect(r.vendor).toBe("Palo Alto Networks");
    expect(r.product).toBe("PAN-OS");
    expect(r.cvss).toMatchObject({ score: 10, severity: "CRITICAL" });
    expect(r.ssvc).toEqual({ exploitation: "active", automatable: "yes", impact: "total" });
    expect(r.kevAdded).toBe("2024-04-12");
    expect(r.affected[0].fixed).toEqual(["11.1.2-h3", "11.0.4-h1", "10.2.9-h1"]);
    expect(r.solutions[0]).toMatch(/fixed in PAN-OS 10\.2\.9-h1/);
    expect(r.references[0]).toMatchObject({ url: "https://security.paloaltonetworks.com/CVE-2024-3400" });
  });

  it("falls back to CISA's ADP score and handles odd version ranges (Log4Shell)", () => {
    const r = parseCveRecord(fixture("CVE-2021-44228.json"));
    expect(r.cvss?.score).toBe(10);
    expect(r.affected[0].fixed).toEqual(["2.15.0", "2.12.2", "2.3.1"]);
    expect(r.affected[0].ranges[0]).toBe("2.0-beta9 and later");
  });
});

describe("versions", () => {
  it("orders hotfix suffixes and multi-digit parts naturally", () => {
    expect(compareVersions("10.2.10", "10.2.9-h1")).toBeGreaterThan(0);
    expect(compareVersions("11.0.4-h1", "11.0.4")).toBeGreaterThan(0);
    expect(compareVersions("2.12.2", "2.3.1")).toBeGreaterThan(0);
  });

  it("describes open-ended ranges in plain words", () => {
    const out = summarizeAffected([
      { vendor: "Acme", product: "Gate", versions: [{ version: "0", lessThan: "4.2.1", status: "affected" }] },
      { vendor: "Acme", product: "Hub", versions: [{ version: "1.0", lessThanOrEqual: "1.4", status: "affected" }] },
    ]);
    expect(out[0]).toMatchObject({ ranges: ["Before 4.2.1"], fixed: ["4.2.1"] });
    expect(out[1]).toMatchObject({ ranges: ["1.0 through 1.4"], fixed: [] });
  });
});

describe("EPSS", () => {
  it("reads string scores from the FIRST envelope", () => {
    const scores = parseEpss({
      status: "OK",
      "status-code": 200,
      data: [
        { cve: "CVE-2024-3400", epss: "0.94352", percentile: "0.99957", date: "2026-11-16" },
        { cve: "garbage", epss: "x", percentile: "y", date: "" },
      ],
    });
    expect(Object.keys(scores)).toEqual(["CVE-2024-3400"]);
    expect(scores["CVE-2024-3400"].score).toBeCloseTo(0.94352);
  });

  it("chunks long CVE lists", () => {
    expect(chunk([1, 2, 3, 4, 5], 2)).toEqual([[1, 2], [3, 4], [5]]);
  });
});

describe("ENISA EUVD", () => {
  // Same shape and value formats as a live /api/exploitedvulnerabilities record.
  const record = {
    id: "EUVD-2026-102427",
    enisaUuid: "62908a97-686c-3466-8dbf-36ed9b125452",
    description: "Sample description of a remote support flaw.",
    datePublished: "Oct 15, 2026, 8:30:32 PM",
    dateUpdated: "Oct 17, 2026, 3:55:27 AM",
    baseScore: 9.3,
    baseScoreVersion: "4.0",
    baseScoreVector: "AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
    references: "https://nvd.nist.gov/vuln/detail/CVE-2026-102764\nhttps://example.com/advisory\n",
    aliases: "CVE-2026-102764\nGHSA-pf95-v8m2-73q8\n",
    assigner: "BT",
    epss: 1.18,
    exploitedSince: "Oct 16, 2026, 12:00:00 AM",
    enisaIdVendor: [{ id: "314d6e10", vendor: { name: "BeyondTrust" } }],
  };

  it("parses the bare-array shape with human-readable dates", () => {
    const [item] = parseEuvdList([record]);
    expect(item.cves).toEqual(["CVE-2026-102764"]);
    expect(item.published).toBe("2026-10-15T20:30:32.000Z");
    expect(item.exploitedSince).toBe("2026-10-16T00:00:00.000Z");
    expect(item.vendor).toBe("BeyondTrust");
    expect(item.product).toBeNull();
    expect(item.references).toHaveLength(2);
  });

  it("parses the search shape", () => {
    expect(parseEuvdList({ items: [record], total: 1 })).toHaveLength(1);
    expect(() => parseEuvdList({ nope: true })).toThrow();
  });
});

describe("dates and text", () => {
  it("parses EUVD dates as UTC, including a narrow no-break space before PM", () => {
    expect(toIso("Sep 9, 2026, 1:00:31 PM")).toBe("2026-09-09T13:00:31.000Z");
    expect(toIso("Jan 1, 2026, 12:05:00 AM")).toBe("2026-01-01T00:05:00.000Z");
    expect(toIso("2026-11-13T20:24:18.3008Z")).toBe("2026-11-13T20:24:18.300Z");
    expect(toIso("")).toBeNull();
  });

  it("decodes entities and truncates on word boundaries", () => {
    expect(decodeEntities("Fortinet&#8217;s &amp; Cisco&rsquo;s")).toBe("Fortinet’s & Cisco’s");
    expect(truncate("one two three four five", 12)).toBe("one two…");
  });
});

describe("CIRCL sightings", () => {
  it("keeps CVE IDs only and uppercases them", () => {
    const out = parseMostSighted([
      { vulnerability: "cve-2026-1234", count: 12 },
      { vulnerability: "ghsa-abcd-efgh-ijkl", count: 9 },
      { vulnerability: "CVE-2026-1234", count: 3 },
    ]);
    expect(out).toEqual([{ cve: "CVE-2026-1234", count: 12 }]);
  });
});

describe("Have I Been Pwned", () => {
  it("drops fabricated, spam and sensitive breaches and sorts newest first", () => {
    const out = parseBreaches([
      { Name: "Old", Title: "Old Co", Domain: "old.example", AddedDate: "2026-01-01T00:00:00Z", PwnCount: 10, DataClasses: ["Email addresses"], Description: "<p>Old breach. More text.</p>", IsVerified: true },
      { Name: "New", Title: "New Co", Domain: "new.example", AddedDate: "2026-11-10T00:00:00Z", PwnCount: 2500000, DataClasses: ["Passwords"], Description: "In 2026, <a href='#'>New Co</a> was breached. Details.", IsVerified: true },
      { Name: "Fake", IsFabricated: true },
      { Name: "Spam", IsSpamList: true },
    ]);
    expect(out.map((b) => b.name)).toEqual(["New", "Old"]);
    expect(out[0].summary).toBe("In 2026, New Co was breached.");
  });
});

describe("news feeds", () => {
  const rss = `<?xml version="1.0"?><rss version="2.0"><channel><title>X</title>
    <item><title><![CDATA[Fortinet patches CVE-2026-1111 zero-day]]></title><link>https://news.example/a</link><pubDate>Tue, 17 Nov 2026 12:00:00 +0000</pubDate></item>
    <item><title>Second &amp; story</title><link>https://news.example/b</link><pubDate>Mon, 16 Nov 2026 12:00:00 +0000</pubDate></item>
  </channel></rss>`;
  const atom = `<?xml version="1.0"?><feed xmlns="http://www.w3.org/2005/Atom">
    <entry><title type="text">Atom story</title><link rel="replies" href="https://news.example/c#comments"/><link rel="alternate" href="https://news.example/c"/><published>2026-11-17T13:00:00Z</published></entry>
  </feed>`;

  it("parses RSS and Atom", () => {
    const a = parseFeed(rss, "Example");
    expect(a[0]).toMatchObject({ title: "Fortinet patches CVE-2026-1111 zero-day", cves: ["CVE-2026-1111"] });
    expect(a[1].title).toBe("Second & story");
    const b = parseFeed(atom, "Atom");
    expect(b[0]).toMatchObject({ url: "https://news.example/c", published: "2026-11-17T13:00:00.000Z" });
  });

  it("merges, sorts and de-duplicates", () => {
    const merged = mergeNews([parseFeed(rss, "A"), parseFeed(atom, "B"), parseFeed(rss, "C")], 10);
    expect(merged.map((n) => n.url)).toEqual(["https://news.example/c", "https://news.example/a", "https://news.example/b"]);
  });
});
