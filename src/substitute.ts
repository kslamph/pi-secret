import { REF_RE, isValidName } from "./refs.ts";

export interface Ref {
  raw: string;
  name: string;
  start: number;
  end: number;
}

export type SecretResolver = (name: string) => string | undefined;

export function findRefs(text: string): Ref[] {
  const refs: Ref[] = [];
  REF_RE.lastIndex = 0;
  let m: RegExpExecArray | null;
  while ((m = REF_RE.exec(text))) {
    refs.push({ raw: m[0], name: m[1] as string, start: m.index, end: m.index + m[0].length });
  }
  return refs;
}

export function expandRefs(text: string, resolve: SecretResolver): { text: string; used: string[]; missing: string[] } {
  const used: string[] = [];
  const missing: string[] = [];
  const out = text.replace(REF_RE, (raw: string, name: string) => {
    const value = resolve(name);
    if (value === undefined) {
      if (!missing.includes(name)) missing.push(name);
      return raw;
    }
    if (!used.includes(name)) used.push(name);
    return value;
  });
  return { text: out, used, missing };
}

/**
 * Non-reversible digest suffix, so `a-b` and `a_b` cannot collide after
 * sanitization and a derived name leaks nothing about the secret name.
 */
function nameSuffix(name: string): string {
  let h = 0x811c9dc5;
  for (let i = 0; i < name.length; i++) {
    h ^= name.charCodeAt(i);
    h = Math.imul(h, 0x01000193) >>> 0;
  }
  return h.toString(16).padStart(8, "0").slice(0, 4);
}

export function envVarName(name: string): string {
  const sanitized = name.toUpperCase().replace(/[^A-Z0-9]/g, "_").slice(0, 48);
  return `__PISEC_${sanitized}_${nameSuffix(name)}`;
}

export function quoteForPosix(value: string): string {
  return `'${value.replace(/'/g, `'\\''`)}'`;
}

export function assertResolvable(name: string): void {
  if (!isValidName(name)) throw new Error(`invalid secret name: ${name}`);
}
