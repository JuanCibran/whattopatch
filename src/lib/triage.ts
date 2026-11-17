import type { Cvss, Epss, Evidence, KevInfo, Ssvc, Tier } from "./types";

export type Category = "edge" | "browser" | "apple" | "microsoft" | "mobile" | "transfer" | "cms" | "general";

export type Signals = {
  kev: KevInfo | null;
  evidence: Evidence[];
  epss: Epss | null;
  ssvc: Ssvc | null;
  cvss: Cvss | null;
  /** Days since it was listed (KEV) or published. */
  ageDays: number | null;
  category: Category;
};

export const TIER_LABEL: Record<Tier, string> = {
  now: "Now",
  soon: "This week",
  watch: "Watch",
};

const EDGE =
  /\bforti|pan-os|globalprotect|palo alto|\basa\b|adaptive security|firepower|\bftd\b|ios xe|sonicwall|sonicos|\bsma\b|connect secure|policy secure|pulse secure|netscaler|citrix (adc|gateway)|big-?ip|check ?point|routeros|mikrotik|junos|zyxel|draytek|watchguard|sophos firewall|barracuda|\bvpn\b|firewall|\brouter\b|\bivanti\b/;
const BROWSER = /chrom|firefox|mozilla|safari|webkit|\| edge\b|\bv8\b/;
const MOBILE = /android|samsung|qualcomm|^arm\b|\bmali\b|pixel/;
const TRANSFER =
  /moveit|goanywhere|crushftp|\bcleo\b|screenconnect|connectwise|beyondtrust|simplehelp|kaseya|teamviewer|anydesk|solarwinds|wing ftp|commvault|veeam|n-able/;
const CMS = /wordpress|drupal|joomla|magento|adobe commerce/;

/** `text` is the lowercased "vendor | product | title" string. */
export function categoryOf(text: string): Category {
  if (text.startsWith("apple")) return "apple";
  if (BROWSER.test(text)) return "browser";
  if (EDGE.test(text)) return "edge";
  if (TRANSFER.test(text)) return "transfer";
  if (text.startsWith("microsoft")) return "microsoft";
  if (MOBILE.test(text)) return "mobile";
  if (CMS.test(text)) return "cms";
  return "general";
}

export function isExploited(s: Pick<Signals, "kev" | "evidence" | "ssvc">): boolean {
  return Boolean(s.kev) || s.evidence.length > 0 || s.ssvc?.exploitation === "active";
}

export function tierFor(s: Signals): Tier {
  if (isExploited(s)) return "now";
  const epssHigh = s.epss != null && s.epss.score >= 0.1;
  const weaponized = s.ssvc?.exploitation === "poc" && s.ssvc.automatable === "yes";
  const likelyAndSerious = s.epss != null && s.epss.percentile >= 0.95 && (s.cvss?.score ?? 0) >= 7;
  if (epssHigh || weaponized || likelyAndSerious) return "soon";
  return "watch";
}

/** Higher means fix sooner. Used to order lists and pick "Fix this first". */
export function priorityScore(s: Signals): number {
  let score = 0;
  if (s.kev) {
    score += 60;
    if (s.kev.ransomware) score += 15;
    if (s.kev.forensic) score += 15;
  } else if (isExploited(s)) {
    score += 50;
  } else if (s.ssvc?.exploitation === "poc") {
    score += 15;
  }
  if (s.epss) score += 20 * s.epss.score;
  if (s.cvss) score += s.cvss.score;
  if (s.ssvc?.automatable === "yes") score += 3;
  if (s.ssvc?.impact === "total") score += 3;
  if (s.ageDays != null) score += 10 * Math.max(0, 1 - s.ageDays / 30);
  if (s.category === "edge") score += 5;
  return Math.round(score * 10) / 10;
}
