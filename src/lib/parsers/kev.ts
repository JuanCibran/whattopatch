// Pure parsing for the CISA KEV feed. No Next.js imports, so it can be unit-tested.

export type KevEntry = {
  cve: string;
  vendor: string;
  product: string;
  name: string;
  added: string;
  due: string;
  ransomware: boolean;
  /** CISA requires a forensic check for compromise (BOD 26-04), not just patching. */
  forensic: boolean;
  description: string;
  advisories: string[];
  cwes: string[];
};

export type KevCatalog = {
  version: string;
  released: string;
  count: number;
  entries: KevEntry[];
};

type RawKev = {
  catalogVersion?: string;
  dateReleased?: string;
  count?: number;
  vulnerabilities?: Array<Record<string, unknown>>;
};

const CVE_RE = /^CVE-\d{4}-\d{4,}$/;

export function parseKev(raw: unknown): KevCatalog {
  const data = raw as RawKev;
  if (!data || !Array.isArray(data.vulnerabilities)) {
    throw new Error("KEV feed has no vulnerabilities array");
  }
  const entries: KevEntry[] = [];
  for (const v of data.vulnerabilities) {
    const cve = str(v.cveID).toUpperCase();
    if (!CVE_RE.test(cve)) continue;
    entries.push({
      cve,
      vendor: str(v.vendorProject),
      product: str(v.product),
      name: str(v.vulnerabilityName),
      added: str(v.dateAdded),
      due: str(v.dueDate),
      ransomware: str(v.knownRansomwareCampaignUse).toLowerCase() === "known",
      forensic: str(v.forensicTriage).toLowerCase() === "yes",
      description: str(v.shortDescription),
      advisories: advisoryUrlsFromNotes(str(v.notes)),
      cwes: Array.isArray(v.cwes) ? v.cwes.map(String) : [],
    });
  }
  entries.sort((a, b) => (a.added < b.added ? 1 : a.added > b.added ? -1 : a.cve < b.cve ? 1 : -1));
  return {
    version: str(data.catalogVersion),
    released: str(data.dateReleased),
    count: entries.length,
    entries,
  };
}

/**
 * KEV notes hold "label: url ; url ; ..." pairs. Keep vendor and researcher links;
 * drop CISA's directive boilerplate and NVD (we link NVD ourselves).
 */
export function advisoryUrlsFromNotes(notes: string): string[] {
  const urls = notes.match(/https?:\/\/[^\s;]+/g) ?? [];
  const seen = new Set<string>();
  const out: string[] = [];
  for (const raw of urls) {
    const url = raw.replace(/[).,]+$/, "");
    let host = "";
    try {
      host = new URL(url).hostname;
    } catch {
      continue;
    }
    if (host.endsWith("cisa.gov") || host.endsWith("nvd.nist.gov")) continue;
    if (seen.has(url)) continue;
    seen.add(url);
    out.push(url);
  }
  return out;
}

function str(v: unknown): string {
  return typeof v === "string" ? v.trim() : v == null ? "" : String(v).trim();
}
