import { errorMessage } from "../http";
import type { SourceId, SourceResult, SourceStatus } from "../types";

export const SOURCE_NAMES: Record<SourceId, string> = {
  kev: "CISA KEV",
  cve: "CVE Program",
  epss: "FIRST EPSS",
  euvd: "ENISA EUVD",
  circl: "CIRCL Vulnerability-Lookup",
  hibp: "Have I Been Pwned",
  news: "Security news",
};

export function ok<T>(
  id: SourceId,
  data: T,
  extra: Partial<Pick<SourceStatus, "count" | "sourceUpdatedAt">> = {},
): SourceResult<T> {
  return {
    ok: true,
    data,
    status: { id, name: SOURCE_NAMES[id], ok: true, checkedAt: new Date().toISOString(), ...extra },
  };
}

export function fail<T>(id: SourceId, err: unknown): SourceResult<T> {
  return {
    ok: false,
    data: null,
    status: {
      id,
      name: SOURCE_NAMES[id],
      ok: false,
      error: errorMessage(err),
      checkedAt: new Date().toISOString(),
    },
  };
}
