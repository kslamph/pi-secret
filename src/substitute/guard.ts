import type { Vault } from "../vault.ts";
import { findRefs, RESERVED_NAME, type Ref } from "../refs.ts";
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
 * pi-secret is broken, and asks the user to paste the token into a command — the
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
    // Two exemptions, and the second one is a correction.
    //
    // 1. §12h: a non-resolving ref in an inert region is a commit message or a heredoc
    //    body quoting the syntax, not a value denied delivery.
    // 2. The reserved marker is never an error anywhere. No value is ever behind
    //    `{{sec:redacted}}` — it is the text pi-secret itself writes where it masked one
    //    — so refusing the command protected nothing and blocked ordinary work: reading
    //    or patching any file that mentions it, this project's own docs and tests
    //    included. It used to be the one name that could never be prose, which is
    //    exactly backwards.
    //
    // Everything else still errors, and that is the point: a stale ref after /resume, or
    // a typo, must fail loudly rather than run `curl -H 'Bearer {{sec:gh_pat}}'` with a
    // literal placeholder and let the model report success.
    .filter((r) => {
      if (vault.has(r.name)) return true;
      if (r.name === RESERVED_NAME) return false;
      return r.disposition !== "inert";
    })
    .map((r) => ({
      ref: r,
      problem:
        r.disposition === "inert" || vault.has(r.name)
          ? `{{sec:${r.name}}} sits in a shell context that will not expand it (quoted heredoc body, or an unterminated quote). Move it outside, or pass it via an environment variable.`
          : `sec:${r.name} not found. Available: ${names.length ? names.map((n) => `sec:${n}`).join(", ") : "(none — run /sec add)"} Values are never shown.`,
    }));
}
