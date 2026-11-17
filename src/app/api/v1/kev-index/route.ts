import { getKevIndex } from "@/lib/radar";

/**
 * Compact copy of CISA's exploited list for in-browser stack matching.
 * Rows: [cve, vendor, product, name, dateAdded, ransomware (1/0)].
 */
export async function GET() {
  const index = await getKevIndex();
  if (!index) {
    return Response.json({ error: "CISA KEV is unreachable right now. Try again in a few minutes." }, { status: 503 });
  }
  return Response.json(index, {
    headers: { "access-control-allow-origin": "*" },
  });
}
