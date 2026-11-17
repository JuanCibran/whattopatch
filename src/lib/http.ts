import { USER_AGENT } from "./config";

export class SourceError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "SourceError";
  }
}

type FetchOptions = {
  timeoutMs?: number;
  headers?: Record<string, string>;
  /** Seconds to keep the raw response in the platform fetch cache (survives deploys on Vercel). */
  cacheSeconds?: number;
};

export async function request(url: string, opts: FetchOptions = {}): Promise<Response> {
  const { timeoutMs = 12_000, headers = {}, cacheSeconds } = opts;
  const host = safeHost(url);
  let res: Response;
  try {
    res = await fetch(url, {
      headers: {
        "user-agent": USER_AGENT,
        accept: "application/json, application/rss+xml, application/atom+xml, application/xml;q=0.9, */*;q=0.8",
        ...headers,
      },
      signal: AbortSignal.timeout(timeoutMs),
      ...(cacheSeconds ? { cache: "force-cache" as const, next: { revalidate: cacheSeconds } } : {}),
    });
  } catch (err) {
    const reason = err instanceof Error && err.name === "TimeoutError" ? "timed out" : "could not be reached";
    throw new SourceError(`${host} ${reason}`);
  }
  if (!res.ok) throw new SourceError(`${host} answered HTTP ${res.status}`);
  return res;
}

export async function getJson<T = unknown>(url: string, opts?: FetchOptions): Promise<T> {
  const res = await request(url, opts);
  try {
    return (await res.json()) as T;
  } catch {
    throw new SourceError(`${safeHost(url)} sent something that isn't JSON`);
  }
}

export async function getText(url: string, opts?: FetchOptions): Promise<string> {
  const res = await request(url, opts);
  return res.text();
}

export function safeHost(url: string): string {
  try {
    return new URL(url).hostname;
  } catch {
    return url;
  }
}

export function errorMessage(err: unknown): string {
  if (err instanceof SourceError) return err.message;
  if (err instanceof Error) return err.message;
  return String(err);
}
