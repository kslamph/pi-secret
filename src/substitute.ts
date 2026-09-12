import { REF_RE, type SecretResolver } from "./refs.ts";

export { envVarName, findRefs, type Ref, type SecretResolver } from "./refs.ts";
export { expandBash, heredocRegions, type BashExpansion } from "./substitute/bash.ts";

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
