import { fmtDate, fmtPercentile, fmtProbability, orList, productName } from "./format";
import { daysBetween } from "./parsers/util";
import type { Category } from "./triage";
import type { Advice, AdviceStep, Cvss, Epss, Evidence, KevInfo, Ssvc, Tier } from "./types";

export type AdviceInput = {
  tier: Tier;
  kev: KevInfo | null;
  evidence: Evidence[];
  epss: Epss | null;
  ssvc: Ssvc | null;
  cvss: Cvss | null;
  category: Category;
  vendor: string;
  product: string;
  fixed: string[];
  advisory: string | null;
  /** True when the link comes from the vendor (KEV notes or a vendor-advisory reference). */
  advisoryIsVendor?: boolean;
  /** When the advice is generated; used to phrase deadlines. */
  asOf: string;
};

const CATEGORY_STEP: Record<Category, AdviceStep> = {
  edge: {
    title: "Take it off the internet until it's patched",
    detail:
      "If its management page or VPN portal is reachable from the internet, limit access to trusted IPs or your VPN until the update is in.",
  },
  browser: {
    title: "Restart the browser",
    detail:
      "The update only takes effect after a restart. In a company, push it through your browser policy and force the relaunch.",
  },
  apple: {
    title: "Update every Apple device",
    detail:
      "iPhone and iPad: Settings > General > Software Update. Mac: System Settings > General > Software Update.",
  },
  microsoft: {
    title: "Roll out this month's Microsoft updates",
    detail: "Use Windows Update, WSUS or Intune, then reboot. Confirm that servers actually restarted.",
  },
  mobile: {
    title: "Update the phones",
    detail: "Install the latest security update from Settings. Replace devices that no longer receive updates.",
  },
  transfer: {
    title: "Check who has logged in",
    detail:
      "Ransomware crews go after file-transfer and remote-access tools. After patching, review admin accounts, recent logins and unfamiliar files.",
  },
  cms: {
    title: "Update the site and its plugins",
    detail: "Update the core and every plugin. If there is no fix yet, disable the affected plugin.",
  },
  general: {
    title: "Can't patch today?",
    detail: "Apply the vendor's workaround, or disconnect the affected system until you can patch.",
  },
};

function fixedPhrase(fixed: string[]): string | null {
  if (!fixed.length) return null;
  const shown = fixed.slice(0, 3);
  const branchNote = fixed.length > 1 ? " (whichever matches the version you run)" : "";
  return `${orList(shown)} or later${branchNote}`;
}

function patchDetail(input: AdviceInput, when: string): string {
  const vendor = (input.vendor || "the vendor").replace(/\.+$/, "");
  const multiple = /multiple products/i.test(input.product);
  const target = multiple ? "" : productName(input.vendor, input.product);
  const fixed = fixedPhrase(input.fixed);
  if (fixed && target) return `${when} update ${target} to ${fixed}.`;
  if (fixed) return `${when} install ${vendor}'s update: ${fixed}.`;
  const where = input.advisory && input.advisoryIsVendor ? "The vendor advisory lists" : "Check the vendor's site for";
  return `${when} install the fix from ${vendor}. ${where} the fixed versions.`;
}

export function whyLine(input: AdviceInput): string {
  const { kev, evidence, epss, ssvc, cvss, tier } = input;
  if (tier === "now") {
    if (kev) {
      const extras: string[] = [];
      if (kev.ransomware) extras.push("ransomware gangs among them");
      const base = `Attackers are already exploiting this${extras.length ? `, ${extras.join(", ")}` : ""}.`;
      return kev.forensic ? `${base} CISA treats it as a likely break-in, not just a missing patch.` : base;
    }
    if (evidence.includes("enisa")) return "ENISA lists this as exploited in the wild.";
    if (evidence.includes("circl-exploited")) return "Security teams have reported attacks using this flaw.";
    return "CISA's analysis marks exploitation of this flaw as active.";
  }
  if (tier === "soon") {
    if (epss && epss.score >= 0.1) {
      return `There's a ${fmtProbability(epss.score)} chance attackers exploit this in the next 30 days, higher than ${fmtPercentile(epss.percentile)} of all known vulnerabilities.`;
    }
    if (ssvc?.exploitation === "poc" && ssvc.automatable === "yes") {
      return "Exploit code is public and the attack can be automated.";
    }
    if (epss) {
      return `It's more likely to be exploited than ${fmtPercentile(epss.percentile)} of all known vulnerabilities, and it's rated ${cvss ? `${cvss.score} out of 10` : "serious"}.`;
    }
    return "Exploitation looks likely soon.";
  }
  return cvss
    ? `Rated ${cvss.score} out of 10 for severity, but there are no reports of attacks yet.`
    : "Rated critical, but there are no reports of attacks yet.";
}

export function buildAdvice(input: AdviceInput): Advice {
  const steps: AdviceStep[] = [];
  const vendorLink = input.advisory
    ? { href: input.advisory, hrefLabel: input.advisoryIsVendor ? "Vendor advisory" : "Details" }
    : {};

  if (input.tier === "now") {
    const urgent = Boolean(input.kev?.forensic) || (input.kev ? daysBetween(input.kev.added, input.kev.due) <= 3 : false);
    steps.push({ title: urgent ? "Patch today" : "Patch now", detail: patchDetail(input, "Today,"), ...vendorLink });
    steps.push({ ...CATEGORY_STEP[input.category] });
    if (input.kev?.forensic || input.kev?.ransomware) {
      steps.push({
        title: "Check for a break-in",
        detail: `Patching doesn't remove an attacker who's already in. Look for new admin accounts, unexpected files or scheduled tasks, and unusual outbound traffic, and check the vendor's indicators of compromise.${
          input.kev?.ransomware ? " Make sure your backups are offline and restorable." : ""
        }`,
      });
    }
    if (input.kev?.due) {
      const days = daysBetween(input.kev.added, input.kev.due);
      const passed = input.kev.due < input.asOf.slice(0, 10);
      steps.push({
        title: passed ? `CISA's deadline passed on ${fmtDate(input.kev.due, input.asOf)}` : `Deadline: ${fmtDate(input.kev.due, input.asOf)}`,
        detail: `CISA gave US federal agencies ${days} ${days === 1 ? "day" : "days"} to fix this. Treat that as your outer limit${passed ? ", and you're past it" : ""}.`,
      });
    }
  } else if (input.tier === "soon") {
    steps.push({ title: "Patch within 7 days", detail: patchDetail(input, "In your next maintenance window,"), ...vendorLink });
    steps.push({
      title: "Internet-facing systems first",
      detail: "If this runs on anything reachable from the internet, patch those systems before internal ones.",
    });
    if (input.category !== "general") steps.push({ ...CATEGORY_STEP[input.category] });
  } else {
    steps.push({ title: "Patch in your normal cycle", detail: patchDetail(input, "In your regular patch window,"), ...vendorLink });
    steps.push({
      title: "We'll flag it if that changes",
      detail: "It moves to Now if attackers start using it, or to This week if exploitation becomes likely.",
    });
  }

  return { why: whyLine(input), steps };
}
