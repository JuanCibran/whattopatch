import { SITE } from "@/lib/config";
import { fmtDate, productName } from "@/lib/format";
import { getRadar } from "@/lib/radar";
import { getKev } from "@/lib/sources/kev";

/**
 * Daily digest, triggered by the Vercel cron in vercel.json.
 * Sends newly exploited vulnerabilities (and the top "This week" items) to whichever
 * channels are configured: Telegram, Discord and/or Slack. Protected by CRON_SECRET.
 */
export async function GET(request: Request) {
  const secret = process.env.CRON_SECRET;
  if (!secret || request.headers.get("authorization") !== `Bearer ${secret}`) {
    return Response.json({ error: "Unauthorized" }, { status: 401 });
  }

  const params = new URL(request.url).searchParams;
  const days = Math.min(7, Math.max(1, Number(params.get("days")) || 1));
  const force = params.get("force") === "1";
  const now = new Date();
  const since = new Date(now.getTime() - days * 86_400_000).toISOString().slice(0, 10);

  const [kevRes, radar] = await Promise.all([getKev(), getRadar()]);
  if (!kevRes.ok) {
    return Response.json({ error: `CISA KEV unreachable: ${kevRes.status.error}` }, { status: 502 });
  }

  const fresh = kevRes.data.entries.filter((e) => e.added >= since);
  const byCve = new Map(radar.now.map((i) => [i.cve, i]));
  const lines: string[] = [];

  if (fresh.length) {
    lines.push(`${SITE.name}: ${fresh.length} newly exploited ${fresh.length === 1 ? "vulnerability" : "vulnerabilities"}`);
    for (const e of fresh.slice(0, 10)) {
      const item = byCve.get(e.cve);
      const flags = [e.ransomware ? "ransomware" : "", e.forensic ? "check for compromise" : ""].filter(Boolean).join(", ");
      lines.push("");
      lines.push(`${productName(e.vendor, e.product)}: ${e.name} (${e.cve})${flags ? ` [${flags}]` : ""}`);
      if (item) lines.push(`${item.advice.steps[0].title}. ${item.advice.steps[0].detail}`);
      if (e.due) lines.push(`CISA deadline: ${fmtDate(e.due, now.toISOString())}`);
      lines.push(`${SITE.url}/cve/${e.cve}`);
    }
    if (fresh.length > 10) lines.push("", `And ${fresh.length - 10} more: ${SITE.url}/#now`);
  }

  const soon = radar.soon.slice(0, 3).filter((i) => i.cve);
  if (soon.length) {
    lines.push("", "Likely to be exploited soon:");
    for (const i of soon) lines.push(`${productName(i.vendor, i.product)} (${i.cve}): ${SITE.url}/cve/${i.cve}`);
  }

  if (!fresh.length && !force) {
    return Response.json({ sent: [], newExploited: 0, note: `Nothing new on CISA's list since ${since}.` });
  }
  if (!fresh.length) lines.unshift(`${SITE.name}: nothing new on CISA's exploited list since ${since}.`);

  const text = lines.join("\n");
  if (params.get("preview") === "1") {
    return new Response(text, { headers: { "content-type": "text/plain; charset=utf-8" } });
  }
  const sent: string[] = [];
  const failed: string[] = [];

  async function post(name: string, url: string, body: unknown) {
    try {
      const res = await fetch(url, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(body),
        signal: AbortSignal.timeout(10_000),
      });
      (res.ok ? sent : failed).push(name);
    } catch {
      failed.push(name);
    }
  }

  const tasks: Promise<void>[] = [];
  if (process.env.TELEGRAM_BOT_TOKEN && process.env.TELEGRAM_CHAT_ID) {
    tasks.push(
      post("telegram", `https://api.telegram.org/bot${process.env.TELEGRAM_BOT_TOKEN}/sendMessage`, {
        chat_id: process.env.TELEGRAM_CHAT_ID,
        text: text.slice(0, 4000),
        link_preview_options: { is_disabled: true },
      }),
    );
  }
  if (process.env.DISCORD_WEBHOOK_URL) {
    tasks.push(post("discord", process.env.DISCORD_WEBHOOK_URL, { content: text.slice(0, 1990) }));
  }
  if (process.env.SLACK_WEBHOOK_URL) {
    tasks.push(post("slack", process.env.SLACK_WEBHOOK_URL, { text }));
  }
  await Promise.all(tasks);

  return Response.json({ sent, failed, newExploited: fresh.length, configured: tasks.length });
}
