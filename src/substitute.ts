import { REF_RE } from "./refs.ts";

export { envVarName } from "./refs.ts";

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

export function quoteForPosix(value: string): string {
  return `'${value.replace(/'/g, `'\\''`)}'`;
}
