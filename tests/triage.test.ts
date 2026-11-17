import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { fmtProbability, fmtPercentile, orList, productName } from "../src/lib/format";
import { buildItem } from "../src/lib/item";
import { parseCveRecord } from "../src/lib/parsers/cve";
import { parseKev } from "../src/lib/parsers/kev";
import { decodeStack, entryFor, entryMatches, matchText, STACK_CATALOG } from "../src/lib/stack";
import { categoryOf, tierFor } from "../src/lib/triage";

const fixture = (name: string) => JSON.parse(readFileSync(join(__dirname, "fixtures", name), "utf8"));
const kev = parseKev(fixture("kev-sample.json"));
const asOf = "2026-11-17T14:00:00.000Z";

describe("tiers", () => {
  const base = { kev: null, evidence: [], epss: null, ssvc: null, cvss: null, ageDays: 2, category: "general" as const };

  it("puts anything exploited in Now", () => {
    expect(tierFor({ ...base, kev: { added: "2026-11-13", due: "2026-11-16", ransomware: false, forensic: true } })).toBe("now");
    expect(tierFor({ ...base, evidence: ["enisa"] })).toBe("now");
    expect(tierFor({ ...base, ssvc: { exploitation: "active", automatable: null, impact: null } })).toBe("now");
  });

  it("puts likely exploitation in This week", () => {
    expect(tierFor({ ...base, epss: { score: 0.2, percentile: 0.96, date: "" } })).toBe("soon");
    expect(tierFor({ ...base, ssvc: { exploitation: "poc", automatable: "yes", impact: "total" } })).toBe("soon");
  });

  it("puts critical-but-quiet in Watch", () => {
    expect(
      tierFor({ ...base, cvss: { score: 9.8, severity: "CRITICAL", version: "3.1", vector: null }, epss: { score: 0.004, percentile: 0.6, date: "" } }),
    ).toBe("watch");
  });
});

describe("items and advice", () => {
  it("builds a Now item for PAN-OS with fixed versions in the first step", () => {
    const record = parseCveRecord(fixture("CVE-2024-3400.json"));
    const entry = kev.entries.find((e) => e.cve === "CVE-2024-3400")!;
    const item = buildItem({ cve: entry.cve, kev: entry, record, epss: { score: 0.94, percentile: 0.999, date: "2026-11-16" }, asOf });
    expect(item.tier).toBe("now");
    expect(item.advice.steps[0].title).toMatch(/^Patch/);
    expect(item.advice.steps[0].detail).toContain("11.1.2-h3");
    expect(item.advice.steps[0].href).toBeTruthy();
    expect(item.advice.steps.some((s) => s.title.startsWith("Take it off the internet"))).toBe(true);
    expect(item.matchText.startsWith("palo alto networks | pan-os")).toBe(true);
  });

  it("asks for a compromise check when CISA requires forensic triage", () => {
    const forensic = kev.entries.find((e) => e.forensic)!;
    const item = buildItem({ cve: forensic.cve, kev: forensic, asOf });
    expect(item.advice.why).toMatch(/break-in/);
    expect(item.advice.steps.map((s) => s.title)).toContain("Check for a break-in");
    expect(item.advice.steps[0].title).toBe("Patch today");
  });

  it("explains EPSS in plain words for This week", () => {
    const item = buildItem({
      cve: "CVE-2026-0001",
      record: null,
      euvd: {
        euvdId: "EUVD-2026-1",
        cves: ["CVE-2026-0001"],
        description: "Remote code execution in Example Gateway.",
        published: "2026-11-15T00:00:00.000Z",
        updated: null,
        score: 9.8,
        scoreVersion: "3.1",
        vector: null,
        vendor: "Example",
        product: "Gateway",
        references: ["https://example.com/advisory"],
        exploitedSince: null,
        assigner: null,
      },
      epss: { score: 0.31, percentile: 0.97, date: "2026-11-16" },
      asOf,
    });
    expect(item.tier).toBe("soon");
    expect(item.advice.why).toBe(
      "There's a 31% chance attackers exploit this in the next 30 days, higher than 97% of all known vulnerabilities.",
    );
    expect(item.advice.steps[0].title).toBe("Patch within 7 days");
  });
});

describe("advice wording on real records", () => {
  it("names the product people know and keeps brand casing", () => {
    const record = parseCveRecord(fixture("CVE-2026-46300.json"));
    const item = buildItem({ cve: record.id, record, asOf });
    expect(item.vendor).toBe("Linux");
    expect(item.advice.steps[0].detail).toMatch(/update Linux to 7\.1, 7\.0\.10 or 6\.18\.33 or later/);
    const apple = buildItem({
      cve: "CVE-2024-27834",
      kev: { cve: "CVE-2024-27834", vendor: "Apple", product: "Multiple Products", name: "Apple Multiple Products Improper Authentication Vulnerability", added: "2026-11-04", due: "2026-11-18", ransomware: false, forensic: false, description: "", advisories: ["https://support.apple.com/en-us/120896"], cwes: [] },
      asOf,
    });
    expect(apple.advice.steps[0].detail).toBe("Today, install the fix from Apple. The vendor advisory lists the fixed versions.");
    expect(apple.advice.steps.some((s) => s.detail.startsWith("iPhone and iPad"))).toBe(true);
  });

  it("treats n/a vendors as unknown and labels non-vendor links honestly", () => {
    const item = buildItem({
      cve: "CVE-2023-38646",
      record: { ...parseCveRecord(fixture("CVE-2024-3400.json")), vendor: "n/a", product: "n/a", references: [{ url: "https://example.com/writeup", tags: [], name: null }] },
      extraEvidence: ["circl-exploited"],
      asOf,
    });
    expect(item.vendor).toBe("");
    expect(item.advice.steps[0].hrefLabel).toBe("Details");
    expect(item.advice.steps[0].detail).not.toContain("n/a");
  });
});

describe("categories", () => {
  it("recognizes edge devices, browsers and Apple", () => {
    expect(categoryOf(matchText("Fortinet", "FortiOS", "FortiOS SSL-VPN overflow"))).toBe("edge");
    expect(categoryOf(matchText("Google", "Chromium V8", "Type confusion"))).toBe("browser");
    expect(categoryOf(matchText("Apple", "Multiple Products", "WebKit memory corruption"))).toBe("apple");
    expect(categoryOf(matchText("Microsoft", "Windows", "CLFS driver"))).toBe("microsoft");
  });
});

describe("stack matching", () => {
  const text = (v: string, p: string, t: string) => matchText(v, p, t);
  const m = (id: string, t: string) => entryMatches(entryFor(id)!, t);

  it("matches the products people expect", () => {
    expect(m("fortinet", text("Fortinet", "FortiOS", "FortiOS heap overflow"))).toBe(true);
    expect(m("chromium", text("Google", "Chromium V8", "Chromium V8 type confusion"))).toBe(true);
    expect(m("chromium", text("Microsoft", "Edge", "Edge memory corruption"))).toBe(true);
    expect(m("ms-exchange", text("Microsoft", "Exchange Server", "Exchange deserialization"))).toBe(true);
    expect(m("cisco-ios", text("Cisco", "IOS XE", "IOS XE web UI privilege escalation"))).toBe(true);
  });

  it("avoids the obvious false positives", () => {
    expect(m("apple", text("Cisco", "IOS XE", "IOS XE web UI"))).toBe(false);
    expect(m("ms-office", text("Microsoft", "Windows", "Windows weak password requirement"))).toBe(false);
    expect(m("qualcomm", text("Acme", "Router", "Malicious firmware upload"))).toBe(false);
    expect(m("cisco", text("Acme", "Router", "Works like Cisco"))).toBe(false);
  });

  it("matches every real KEV entry from at least one big vendor", () => {
    const vendors = ["microsoft", "fortinet", "cisco", "apple", "chromium", "ivanti", "vmware"];
    const hits = vendors.map((id) => kev.entries.filter((e) => m(id, text(e.vendor, e.product, e.name))).length);
    expect(hits.reduce((a, b) => a + b, 0)).toBeGreaterThan(10);
  });

  it("supports custom keywords and drops unknown ids from links", () => {
    expect(entryFor("kw:jenkins")?.label).toBe("jenkins");
    expect(m("kw:jenkins", text("Jenkins", "Jenkins", "Script console RCE"))).toBe(true);
    expect(decodeStack("fortinet,kw%3Ajenkins,not-real,fortinet")).toEqual(["fortinet", "kw:jenkins"]);
  });

  it("has unique ids and valid regexes", () => {
    const ids = STACK_CATALOG.map((e) => e.id);
    expect(new Set(ids).size).toBe(ids.length);
    for (const e of STACK_CATALOG) {
      expect(() => new RegExp(e.any, "i")).not.toThrow();
      const all = e.all;
      if (all) expect(() => new RegExp(all, "i")).not.toThrow();
    }
  });
});

describe("formatting", () => {
  it("formats probabilities and lists", () => {
    expect(fmtProbability(0.9412)).toBe("94%");
    expect(fmtProbability(0.042)).toBe("4.2%");
    expect(fmtProbability(0.0004)).toBe("<0.1%");
    expect(fmtPercentile(0.9996)).toBe("99%");
    expect(orList(["a", "b", "c"])).toBe("a, b or c");
    expect(productName("Barracuda Networks", "Barracuda Email Security Gateway (ESG)")).toBe("Barracuda Email Security Gateway (ESG)");
    expect(productName("Check Point", "Multiple Products")).toBe("Check Point (multiple products)");
    expect(productName("Palo Alto Networks", "PAN-OS")).toBe("Palo Alto Networks PAN-OS");
  });
});
