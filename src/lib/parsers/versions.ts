export type AffectedSummary = {
  vendor: string;
  product: string;
  /** Plain-language affected ranges, e.g. "11.0.0 up to 11.0.4-h1". */
  ranges: string[];
  /** First fixed version of each affected branch, newest first. */
  fixed: string[];
};

type VersionEntry = {
  version?: unknown;
  status?: unknown;
  lessThan?: unknown;
  lessThanOrEqual?: unknown;
  changes?: Array<{ at?: unknown; status?: unknown }>;
};

type AffectedEntry = {
  vendor?: unknown;
  product?: unknown;
  defaultStatus?: unknown;
  versions?: VersionEntry[];
};

export function isVersionLike(value: string): boolean {
  return /\d/.test(value) && !/[*\s]/.test(value) && value.length <= 40;
}

/** Natural comparison for dotted versions with suffixes (10.2.9-h1 < 10.2.10). */
export function compareVersions(a: string, b: string): number {
  const pa = a.split(/[^0-9a-z]+/i).filter(Boolean);
  const pb = b.split(/[^0-9a-z]+/i).filter(Boolean);
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
    const x = pa[i];
    const y = pb[i];
    if (x === undefined) return -1;
    if (y === undefined) return 1;
    const nx = /^\d+$/.test(x) ? Number(x) : NaN;
    const ny = /^\d+$/.test(y) ? Number(y) : NaN;
    if (!Number.isNaN(nx) && !Number.isNaN(ny)) {
      if (nx !== ny) return nx - ny;
    } else if (x !== y) {
      return x < y ? -1 : 1;
    }
  }
  return 0;
}

function text(v: unknown): string {
  return typeof v === "string" ? v.trim() : "";
}

export function summarizeAffected(affected: unknown): AffectedSummary[] {
  if (!Array.isArray(affected)) return [];
  const out: AffectedSummary[] = [];
  for (const entry of affected as AffectedEntry[]) {
    const vendor = text(entry.vendor);
    const product = text(entry.product);
    if (!product) continue;
    const ranges: string[] = [];
    const fixed = new Set<string>();
    for (const v of entry.versions ?? []) {
      if (text(v.status) !== "affected") continue;
      const from = text(v.version);
      const below = text(v.lessThan);
      const through = text(v.lessThanOrEqual);
      const openStart = !from || from === "0" || from === "*" || from === "unspecified";
      if (below && isVersionLike(below)) {
        ranges.push(openStart ? `Before ${below}` : `${from} up to ${below}`);
        fixed.add(below);
      } else if (through && isVersionLike(through)) {
        ranges.push(openStart ? `${through} and earlier` : `${from} through ${through}`);
      } else if (below || through) {
        ranges.push(openStart ? "All versions" : `${from} and later`);
      } else if (from && !openStart) {
        ranges.push(from);
      }
      for (const change of v.changes ?? []) {
        const at = text(change.at);
        if (text(change.status) === "unaffected" && isVersionLike(at)) fixed.add(at);
      }
    }
    if (!ranges.length && !fixed.size) continue;
    out.push({
      vendor,
      product,
      ranges: [...new Set(ranges)].slice(0, 12),
      fixed: [...fixed].sort((a, b) => compareVersions(b, a)).slice(0, 12),
    });
  }
  return out;
}
