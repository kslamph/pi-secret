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

/**
 * The shell variable a secret is exported as. `name` is public, so this digest is
 * a collision suppressor, not a secret: 8 hex of sha256 over the *whole* name, so
 * two names that sanitize identically (a-b vs a_b) still differ, and an attacker
 * cannot walk a 16-bit tag offline to force a match.
 *
 * Bound: 8 (prefix) + 40 (sanitized) + 1 + 8 = 57 chars, valid POSIX identifier.
 */
export function envVarName(name: string): string {
  const sanitized = name.toUpperCase().replace(/[^A-Z0-9]/g, "_").slice(0, 40);
  const tag = createHash("sha256").update(name, "utf8").digest("hex").slice(0, 8);
  return `__PISEC_${sanitized}_${tag}`;
}

export function refToken(name: string): string {
  return `{{sec:${name}}}`;
}
