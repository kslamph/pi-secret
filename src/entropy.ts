/**
 * "Does this string look like a credential, or like a hash/path/URL?"
 *
 * These predicates used to live in `scrub.ts`, which is where they were written back when
 * capture was young enough that sharing a module was cheaper than a new file. They then
 * inverted: the scrubber stopped consuming `looksCredentialish` (it masks by anchored
 * prefix and value equality), leaving it with exactly one caller — `capture.ts`. A
 * predicate about capture precision sitting in the masking module is a drift trap: the
 * next person to change the rules for either side has to know the other exists.
 *
 * It is a shared module because BOTH sides need the same denylist, for the same reason.
 * A credential with a long hex tail contains a 40-hex run, so either an overlap-match or
 * an exempt-the-whole-candidate rule judged on a SUBSTRING would leave a real secret
 * fully visible to a logging endpoint. Only a candidate that IS entirely digest-shaped is
 * exempt, and both the scrubber and the capture detector have to agree on that.
 */

/** Shapes that are digests, not credentials. Anchored: only the WHOLE candidate counts. */
const DIGEST_SHAPED = [
  "[0-9a-f]{40}", // git SHA-1
  "[0-9a-f]{64}", // sha256 digest
  "[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", // uuid
  "[0-9a-f]{7}", // short git SHA
];
const DIGEST_ANCHORED = new RegExp(`^(?:${DIGEST_SHAPED.join("|")})$`, "i");

/** Whole-candidate exemption. Never call this on a substring. */
export function isDigestShaped(candidate: string): boolean {
  return DIGEST_ANCHORED.test(candidate);
}

export function shannonEntropy(s: string): number {
  if (!s.length) return 0;
  const freq = new Map<string, number>();
  for (const ch of s) freq.set(ch, (freq.get(ch) ?? 0) + 1);
  let h = 0;
  for (const n of freq.values()) {
    const p = n / s.length;
    h -= p * Math.log2(p);
  }
  return h;
}

/**
 * Capture-side only: a candidate is worth vaulting if it is long enough, is not a digest,
 * is not a URL or a path, and carries enough character-class variety and entropy to be
 * worth a human's attention.
 */
export function looksCredentialish(text: string): boolean {
  const t = text.trim();
  if (t.length < 20) return false;
  if (isDigestShaped(t)) return false; // same anchored exemption, no recompile per call
  if (/^https?:\/\//i.test(t) || (/^[A-Za-z0-9._/-]+$/.test(t) && t.includes("/"))) return false;
  const classes = [/[a-z]/, /[A-Z]/, /[0-9]/, /[^A-Za-z0-9\s]/].filter((r) => r.test(t)).length;
  return classes >= 2 && shannonEntropy(t) > 3.6;
}