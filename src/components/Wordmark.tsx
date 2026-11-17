/** A triage tag with a red tear-off strip, then the name. */
export function TagMark({ size = 28 }: { size?: number }) {
  return (
    <svg width={size * 0.78} height={size} viewBox="0 0 22 28" aria-hidden="true" focusable="false">
      <path d="M3 1h13l5 5v19a2 2 0 0 1-2 2H3a2 2 0 0 1-2-2V3a2 2 0 0 1 2-2z" fill="#fbfcfd" stroke="#17223b" strokeWidth="1.5" />
      <path d="M1.75 19h18.5v6a1.25 1.25 0 0 1-1.25 1.25H3A1.25 1.25 0 0 1 1.75 25z" fill="#c8202f" />
      <path d="M2 18.25h18" stroke="#17223b" strokeWidth="1" strokeDasharray="2 2" />
      <circle cx="11" cy="7" r="2.2" fill="#edf1f5" stroke="#17223b" strokeWidth="1.2" />
    </svg>
  );
}

export function Wordmark() {
  return (
    <span className="inline-flex items-center gap-2.5">
      <TagMark />
      <span className="display text-[1.75rem] leading-none tracking-[0.01em]">WhatToPatch</span>
    </span>
  );
}
