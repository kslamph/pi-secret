import { createHash } from "node:crypto";

/** Shared by injection and scrubbing so both agree on what a ref looks like. */
export const REF_RE = /\{\{sec:([a-z][a-z0-9_-]{0,63})\}\}/g;
export const MAX_REF_BYTES = 1024 * 1024;
/** Guards against a 1-char value chewing up unrelated text. */
export const MIN_SCRUBABLE_LENGTH = 8;

export function isValidName(name: string): boolean {
  return /^[a-z][a-z0-9_-]{0,63}$/.test(name);
}

export function parseRef(text: string): string | undefined {
  const m = /^\{\{sec:([a-z][a-z0-9_-]{0,63})\}\}$/.exec(text);
  return m ? m[1] : undefined;
}

/** 4 hex chars. Derived only from the full value, never from a prefix. */
export function fingerprint(value: string): string {
  return createHash("sha256").update(value, "utf8").digest("hex").slice(0, 4);
}

/** Encodings a tool might echo back for the same underlying secret. */
export function derivedForms(value: string): string[] {
  const buf = Buffer.from(value, "utf8");
  return [value, buf.toString("base64"), buf.toString("base64url"), buf.toString("hex")];
}

export function refToken(name: string): string {
  return `{{sec:${name}}}`;
}
