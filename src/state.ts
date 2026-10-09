import { fingerprint } from "./refs.ts";

let enabled = true;
export function setEnabled(value: boolean): void {
  enabled = value;
}
export function isEnabled(): boolean {
  return enabled;
}

/**
 * Values the user DECLINED when capture asked.
 *
 * Keyed by the same 4-hex fingerprint the labels use, never the value: a decline is a
 * statement about a value, and storing the value to remember the statement would defeat
 * the extension's entire purpose. It also keeps the set bounded — a fingerprint is 2
 * bytes of decision, not a secret.
 *
 * Session-scoped by construction: the module is re-evaluated on `/reload`, and
 * session_start clears it for every non-reload reason, so a value you declined in one
 * project never silently stays declined in the next.
 */
const MAX_DECLINED = 200;
const declined = new Set<string>();

export function isDeclined(value: string): boolean {
  return declined.has(fingerprint(value));
}

/** Remember the decline, oldest-out at the cap so the set cannot grow without bound. */
export function declineValue(value: string): void {
  if (declined.size >= MAX_DECLINED) declined.clear();
  declined.add(fingerprint(value));
}

export function declinedCount(): number {
  return declined.size;
}

export function resetDeclined(): void {
  declined.clear();
}
