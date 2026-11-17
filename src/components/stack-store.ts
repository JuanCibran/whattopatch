"use client";

import { decodeStack, encodeStack } from "@/lib/stack";

/**
 * The user's stack lives in localStorage (and optionally in the URL hash, so a list can be
 * shared). The hash never reaches the server. Read through useSyncExternalStore so the
 * server render and the first client render agree.
 */
const STORAGE_KEY = "wtp.stack.v1";
const listeners = new Set<() => void>();

function hashValue(): string | null {
  return new URLSearchParams(window.location.hash.slice(1)).get("stack");
}

export function subscribe(callback: () => void): () => void {
  listeners.add(callback);
  window.addEventListener("storage", callback);
  window.addEventListener("hashchange", callback);
  return () => {
    listeners.delete(callback);
    window.removeEventListener("storage", callback);
    window.removeEventListener("hashchange", callback);
  };
}

export function getSnapshot(): string {
  const fromHash = hashValue();
  if (fromHash !== null) return fromHash;
  try {
    return window.localStorage.getItem(STORAGE_KEY) ?? "";
  } catch {
    return "";
  }
}

export function getServerSnapshot(): string {
  return "";
}

export function writeStack(ids: string[]): void {
  const clean = decodeStack(encodeStack(ids));
  const value = encodeStack(clean);
  try {
    window.localStorage.setItem(STORAGE_KEY, value);
  } catch {
    // Private mode or storage disabled: the list still works for this visit via the hash.
  }
  if (hashValue() !== null || !canStore()) {
    const url = new URL(window.location.href);
    url.hash = clean.length ? `stack=${value}` : "";
    window.history.replaceState(null, "", url.toString());
  }
  for (const l of listeners) l();
}

function canStore(): boolean {
  try {
    const probe = "wtp.probe";
    window.localStorage.setItem(probe, "1");
    window.localStorage.removeItem(probe);
    return true;
  } catch {
    return false;
  }
}

export function shareUrl(ids: string[]): string {
  const url = new URL(window.location.href);
  url.hash = `stack=${encodeStack(ids)}`;
  return url.toString();
}
