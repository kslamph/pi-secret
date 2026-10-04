import type { Vault } from "../vault.ts";
import { findRefs, type Ref } from "../refs.ts";
import { heredocRegions, scanBash } from "./bash.ts";

export type RefDisposition = "expand" | "inert" | "unknown";

export interface ClassifiedRef extends Ref {
  disposition: RefDisposition;
}

/**
 * Where can a ref actually be delivered, and where must we refuse?
 *
 * Three dispositions, and the middle one is the whole point of this module: a
 * ref in a shell context that performs no expansion would otherwise reach the
 * child as the literal text `{{sec:NAME}}`. The model reads that back, concludes
 * pi-secure is broken, and asks the user to paste the token into a command — the
 * one path this project exists to close. So an unusable ref is reported, never
 * silently executed.
 *
 * `vault` is optional because a caller may want purely lexical classification
 * (is this ref inert?) before any secret exists. Without it, "unknown" is
 * unreachable — a name that is not in the vault you did not supply is not
 * knowable, and guessing "unknown" would report every ref in the command as an
 * error.
 */
export function classifyBashRefs(command: string, vault?: Vault): ClassifiedRef[] {
  const regions = heredocRegions(command);
  const { unterminated } = scanBash(command);
  return findRefs(command).map((ref) => {
    const region = regions.find((r) => ref.start >= r.start && ref.end <= r.end);
    // A quoted delimiter suppresses parameter expansion, so the body is data.
    // A non-inert (unquoted) body DOES expand and is not a problem here.
    const inert = Boolean(region?.inert);
    // A quote left open means the lexer cannot know where it ends, so any ref at
    // or after it may sit inside quoting we cannot see. bash rejects the command
    // as a syntax error anyway; expandBash already reports these as missing, and
    // the guard must agree or a ref would pass here and then run as a literal.
    const afterUnterminated = unterminated !== null && ref.start >= unterminated.index;
    const disposition: RefDisposition = inert || afterUnterminated
      ? "inert"
      : vault && !vault.has(ref.name)
        ? "unknown"
        : "expand";
    return { ...ref, disposition };
  });
}

/**
 * What is wrong with each unusable ref, phrased for the model that wrote the
 * command. Names are not secrets, so an unknown name lists the valid ones: the
 * error is maximally useful and self-correcting in one round trip.
 */
export function bashRefIssues(
  command: string,
  vault: Vault,
): Array<{ ref: ClassifiedRef; problem: string }> {
  const names = vault.names();
  return classifyBashRefs(command, vault)
    .filter((r) => r.disposition !== "expand")
    .map((r) => ({
      ref: r,
      problem:
        r.disposition === "inert"
          ? `{{sec:${r.name}}} sits in a shell context that will not expand it (quoted heredoc body, or an unterminated quote). Move it outside, or pass it via an environment variable.`
          : `sec:${r.name} not found. Available: ${names.length ? names.map((n) => `sec:${n}`).join(", ") : "(none — run /sec add)"} Values are never shown.`,
    }));
}
