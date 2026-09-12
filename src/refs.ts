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
 * The shell variable a secret is exported as.
 *
 * `name` is public - the transcript shows `sec:gh_pat` - so this digest is a
 * collision suppressor, not a secret, and it must resist a *targeted* second
 * preimage: Task 6 derives names from text an untrusted endpoint can steer, and an
 * attacker who knows a victim's name and can land a second name in the vault wants
 * both to resolve to one variable, delivering the wrong credential to a chosen host.
 *
 * Two properties, in order of importance:
 *  - the sanitized body is NOT truncated, so names differing anywhere in their first
 *    64 chars (isValidName caps at 64) already differ here;
 *  - the tag is 64 bits of sha256 over the whole name. 32 bits was breakable: a
 *    40-char window plus an 8-hex tag makes "x"x45+"4a5" and "x"x45+"1y32" collide,
 *    which is a ~2^16 birthday walk. 64 bits makes the targeted search infeasible.
 *
 * Bound: 8 + up to 64 + 1 + 16 = 89 chars, always a valid POSIX identifier.
 */
export function envVarName(name: string): string {
  const sanitized = name.toUpperCase().replace(/[^A-Z0-9]/g, "_");
  const tag = createHash("sha256").update(name, "utf8").digest("hex").slice(0, 16);
  return `__PISEC_${sanitized}_${tag}`;
}

/**
 * Which already-held name, if any, would claim the same shell variable as `name`.
 * Extracted with an injectable resolver so the refusal path is testable: a genuine
 * 64-bit collision cannot be found in a test, and asserting "no collision" on
 * `a-b` vs `a_b` would not exercise the throw at all.
 */
export function findEnvVarCollision(
  existing: Iterable<string>,
  name: string,
  toVar: (n: string) => string = envVarName,
): string | undefined {
  const candidate = toVar(name);
  for (const other of existing) {
    if (other !== name && toVar(other) === candidate) return other;
  }
  return undefined;
}

export function refToken(name: string): string {
  return `{{sec:${name}}}`;
}
