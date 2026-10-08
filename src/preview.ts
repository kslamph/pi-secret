import { matchesProviderFormat, shannonEntropy } from "./entropy.ts";

/**
 * How a secret identifies itself to a human.
 *
 * This started as `sha256:<16 hex>` everywhere, which is sound — one-way, reveals nothing
 * — and useless for the job it was doing: nobody can tell from a digest whether the key
 * they just pasted is the key they meant to paste. Every API-key console solves this the
 * same way, showing a prefix and the last few characters with the middle masked, and
 * adopting that convention is what makes "confirm a capture without echoing the value"
 * usable at all.
 *
 * ## Why the gate is not "is this a key or a password"
 *
 * That question has no good answer, and asking it is what produced the first version of
 * this rule — a length threshold — which was wrong in both directions. Measured entropy
 * (shannonEntropy, bits per character):
 *
 *     API keys (ghp_/sk-ant-/AWS/slack)   4.66 – 5.07   (187 – 233 bits total)
 *     strong generated passwords          4.25 – 4.70   ( 81 – 122 bits total)
 *     passphrase, four words              3.49          ( 98 bits total)
 *     human-chosen passwords              3.38 – 4.12   ( 47 –  82 bits total)
 *
 * Length does not separate them (a 20-character generated password and a 20-character
 * human password are the same length), and neither does entropy per character — the two
 * middle rows OVERLAP. So neither "key" nor "entropy above some number" is the right
 * discriminator.
 *
 * The right question is the boring one: **does showing a few characters meaningfully
 * weaken THIS value?** And that has an answer that does not require categorising anything:
 *
 *   - A recognised provider format (`ghp_`, `sk-ant-`, `AKIA`, `xoxb-`, …) is issued by a
 *     provider, is long, and is machine-random by construction. Showing four characters at
 *     each end costs ~48 bits out of ~190. The prefix is also the most useful part to show,
 *     because it is what identifies the KIND of key.
 *   - A value that is long AND looks machine-random may also be a strong generated
 *     password. Revealing two characters costs ~12 bits out of ~120 — which is not the
 *     failure the length rule was invented to prevent.
 *   - Everything else — passphrases, human-chosen passwords, short values — gets the
 *     digest, exactly as before. A passphrase is where revealing head and tail really
 *     hurts: `correct-ho…ry` gives away that it is English-ish, and an attacker with a
 *     wordlist was going to guess it anyway, but there is no reason to help.
 *
 * The failure modes are asymmetric on purpose. Showing a preview for a weak value costs at
 * most a couple of characters and is bounded by the share rule; refusing to show one for a
 * strong value costs the user a slightly less convenient confirmation and nothing else.
 * When the classifier is unsure it must fall back to hiding, so the entropy threshold sits
 * above the human-password band (4.5) rather than inside it.
 */

const MIN_LENGTH = 20;
const MAX_SIDE = 4;
const SHARE_DIVISOR = 10;
/** Above the human-password band (3.4–4.1), below real keys (4.7+). */
const RANDOM_LOOKING_BITS_PER_CHAR = 4.5;

/** How many characters may be shown at each end. Zero means: show nothing. */
export function revealSides(value: string): number {
  if (value.length < MIN_LENGTH) return 0;
  // A provider format is safe by construction, so it gets the full allowance.
  if (matchesProviderFormat(value)) return MAX_SIDE;
  if (shannonEntropy(value) < RANDOM_LOOKING_BITS_PER_CHAR) return 0;
  return Math.min(MAX_SIDE, Math.floor(value.length / SHARE_DIVISOR));
}

/**
 * The visible format marker of a recognised key — `ghp_`, `sk-ant-`, `AKIA`, `xoxb-` —
 * and the most useful part of a preview, because it is what tells the user which KIND of
 * key they are looking at.
 *
 * Shown ONLY when the whole value matches a known provider format, and never guessed from
 * the value's own shape. Guessing was tried and it is wrong in a way that matters: a
 * "find the leading hyphenated segment" rule reads `xK3-mQ7-` in a random 20-character
 * secret as a prefix and then displays it in full, which spends nine characters of the
 * budget before the share rule has counted a single one. A real console can afford to show
 * a prefix because it KNOWS the format; we can only afford it when the format matches.
 */
function providerPrefix(value: string): string {
  if (!matchesProviderFormat(value)) return "";
  // Greedy over SHORT segments only, so `sk-ant-api03-…` keeps its whole marker while
  // `glpat-abcdefghijkl…` stops at `glpat-` rather than eating eight characters of body.
  const m = /^[A-Za-z0-9]{1,6}(?:[-_][A-Za-z0-9]{1,6})*[-_]/.exec(value);
  if (m) return m[0];
  // `AKIA…`/`ASIA…` have no separator; the marker is the leading capital run.
  const head = /^[A-Z]{4}/.exec(value);
  return head ? head[0] : "";
}

/**
 * `ghp_A1b2…Q7R8`, or undefined when nothing may be shown.
 *
 * The ellipsis is one character rather than a run of dots so two previews line up in a
 * terminal column and do not imply a length the mask does not know.
 */
export function maskPreview(value: string): string | undefined {
  const side = revealSides(value);
  if (side < 1) return undefined;
  const prefix = providerPrefix(value);
  const head = value.slice(prefix.length, prefix.length + side);
  const tail = value.slice(-side);
  return `${prefix}${head}…${tail}`;
}

/**
 * The label shown wherever a secret is identified but not revealed: `/sec list`,
 * `/sec test`, the capture receipt, `sec_list`, the autocomplete, the restore confirmation.
 * Falls back to the sha256 digest, so every entry still has a stable identifier even when
 * no characters may be shown.
 */
export function secretLabel(value: string, digest: string): string {
  return maskPreview(value) ?? `sha256:${digest}`;
}

/** True when `value` would reveal part of it — used by tests to assert the gate. */
export function previewRevealsCharacters(value: string): boolean {
  return maskPreview(value) !== undefined;
}