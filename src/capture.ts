import { findRefs } from "./substitute.ts";
import { isValidName, MIN_SCRUBABLE_LENGTH } from "./refs.ts";
import { looksCredentialish, shannonEntropy } from "./scrub.ts";

export type Confidence = "anchored" | "kv" | "entropy";

export interface Candidate {
  value: string;
  start: number;
  end: number;
  confidence: Confidence;
  hint?: string;
}

const ANCHORED: Array<{ re: RegExp; hint: string }> = [
  { re: /dckr_pat_[A-Za-z0-9_\-]{20,}/g, hint: "docker_pat" },
  { re: /github_pat_[A-Za-z0-9_]{20,}/g, hint: "github_pat" },
  { re: /gh[pousr]_[A-Za-z0-9]{20,}/g, hint: "github" },
  { re: /sk-ant-[A-Za-z0-9_\-]{20,}/g, hint: "anthropic" },
  { re: /AIza[0-9A-Za-z_\-]{30,}/g, hint: "google" },
  { re: /(?:AKIA|ASIA)[0-9A-Z]{16}/g, hint: "aws_access_key_id" },
  { re: /xox[baprs]-[A-Za-z0-9\-]{10,}/g, hint: "slack" },
  { re: /glpat-[A-Za-z0-9_\-]{20,}/g, hint: "gitlab" },
  { re: /npm_[A-Za-z0-9]{30,}/g, hint: "npm" },
  { re: /pypi-Po-[A-Za-z0-9]{20,}/g, hint: "pypi" },
  { re: /hf_[A-Za-z0-9]{20,}/g, hint: "huggingface" },
];

const JWT_RE = /eyJ[A-Za-z0-9_\-]{5,}\.eyJ[A-Za-z0-9_\-]{5,}\.[A-Za-z0-9_\-]{8,}/g;
const PEM_RE = /-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z0-9 ]*PRIVATE KEY-----/g;
// A: KV value classes. The BARE form stops at whitespace and quotes and deliberately ALLOWS
// `&` and `\` to match Task 5's scrub class; excluding them leaked a tail in the clear.
// C: the QUOTED forms capture the interior of `="..."` / `='...'` whole (whitespace included)
// to the matching closing quote. A quoted value is NOT extended by A (the interior is already
// whole); an UNCLOSED quote matches neither form and yields no candidate. J: the keyword must
// sit at a SEGMENT boundary (lookbehind/lookahead) so `my_key=` matches but `monkey=`,
// `turnkey=`, `keyboard=` do not; and a JSON-escaped opening/closing quote (`\"`) is accepted.
const KV_BARE_RE =
  /([A-Za-z0-9_\-]*(?<![A-Za-z0-9])(?:token|secret|password|passwd|pwd|api[_-]?key|authorization|access[_-]?key|credential|cred|url|auth|key)(?![A-Za-z0-9_-])[A-Za-z0-9_\-]*)["']?\s*[=:]\s*([^\s"'<>]{8,})/gi;
const KV_DQUOTE_RE =
  /([A-Za-z0-9_\-]*(?<![A-Za-z0-9])(?:token|secret|password|passwd|pwd|api[_-]?key|authorization|access[_-]?key|credential|cred|url|auth|key)(?![A-Za-z0-9_-])[A-Za-z0-9_\-]*)["']?\s*[=:]\s*\\?"([^"\\]{8,}?)\\?"/gi;
const KV_SQUOTE_RE =
  /([A-Za-z0-9_\-]*(?<![A-Za-z0-9])(?:token|secret|password|passwd|pwd|api[_-]?key|authorization|access[_-]?key|credential|cred|url|auth|key)(?![A-Za-z0-9_-])[A-Za-z0-9_\-]*)["']?\s*[=:]\s*\\?'([^'\\]{8,}?)\\?'/gi;

const DENY_RE =
  /^[0-9a-f]{7}$|^[0-9a-f]{40}$|^[0-9a-f]{64}$|^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

function collect(text: string, re: RegExp, confidence: Confidence, hint?: string): Candidate[] {
  const out: Candidate[] = [];
  re.lastIndex = 0;
  let m: RegExpExecArray | null;
  while ((m = re.exec(text))) {
    const value = confidence === "kv" ? (m[2] as string) : (m[0] as string);
    const full = m[0] as string;
    // Locate the value within the full match rather than assuming it is the trailing
    // token: the QUOTED KV regexes have a closing quote AFTER the value, so
    // (full.length - value.length) would over-count by the delimiter's length and shift
    // the start past the value. indexOf finds the real offset (skipping the opening quote).
    const valIdx = full.indexOf(value);
    const start = m.index + valIdx;
    out.push({ value, start, end: start + value.length, confidence, hint: hint ?? m[1] });
  }
  return out;
}

/** Remove candidates swallowed by a longer one, keeping the widest match. */
function dedupe(candidates: Candidate[]): Candidate[] {
  const sorted = [...candidates].sort((a, b) => a.start - b.start || b.end - a.end);
  const kept: Candidate[] = [];
  for (const c of sorted) {
    const last = kept[kept.length - 1];
    if (last && c.start < last.end) {
      if (c.end > last.end) kept[kept.length - 1] = c;
      continue;
    }
    kept.push(c);
  }
  return kept;
}

/**
 * A KV value class stops at `<`, `>`, `"`, `'` (and whitespace) — but NOT at `&` or
 * `\`, which are allowed here to match Task 5's scrub class. If the value stopped at one
 * of those non-whitespace boundaries while more non-whitespace characters follow, the
 * remaining tail is still part of the same whitespace-free token and would be left in
 * clear after capture: a confidentiality leak that reaches the transcript and the request
 * while the receipt announces success. Extend the candidate to the END of the
 * whitespace-free token so a match can never end inside a credential.
 *
 * This makes over-capture possible: `password=abc&&echo` is one whitespace-free token and
 * is captured whole, mangling a chained command. That is the ACCEPTED direction. A mangled
 * submission is visible to the user and reversible via the capture receipt and `/sec
 * restore`; a leaked tail is neither visible nor reversible. Prefer the visible, reversible
 * failure over the silent leak.
 */
function extendKvToToken(c: Candidate, text: string): Candidate {
  let end = c.start;
  while (end < text.length && !/\s/.test(text[end]!)) end++;
  c.value = text.slice(c.start, end);
  c.end = end;
  return c;
}

/**
 * G: trim stray delimiters from BOTH ends of a captured value. `extendKvToToken` walks to the
 * next whitespace, which re-absorbs characters the value class correctly excluded — a stray
 * trailing quote, backtick, bracket/paren, or sentence punctuation ends up stored in the vault
 * and later substituted as part of the credential. Trim quotes, backtick, brackets/parens and
 * `.,;:!?` from each end, but NOT `=`, `+`, `/`, `-`, `_` (a base64 value legitimately ends in
 * `=` padding, and `-`/`_` are word separators). `password=<placeholder>` is intentionally left
 * uncaptured: angle brackets are excluded and `<your-token-here>` is a template, not a secret.
 */
const DELIM_LEFT = /^["'`\`\]\[)(}{.,;:!?]+/;
const DELIM_RIGHT = /["'`\`\]\[)(}{.,;:!?]+$/;
function trimDelimiters(v: string): { value: string; left: number; right: number } {
  const left = v.length - v.replace(DELIM_LEFT, "").length;
  const right = v.length - v.replace(DELIM_RIGHT, "").length;
  return { value: v.slice(left, v.length - right), left, right };
}

/** Finalize a KV candidate: extend to whitespace (bare only), trim delimiters, adjust spans. */
function finalizeKv(c: Candidate, text: string, extend: boolean): Candidate | null {
  let cand = c;
  if (extend) cand = extendKvToToken(cand, text);
  const t = trimDelimiters(cand.value);
  if (t.value.length < MIN_SCRUBABLE_LENGTH) return null;
  return { ...cand, value: t.value, start: cand.start + t.left, end: cand.end - t.right };
}

export function findCandidates(text: string): Candidate[] {
  if (!text.trim()) return [];
  const reserved: Array<{ start: number; end: number }> = findRefs(text).map((r) => ({
    start: r.start,
    end: r.end,
  }));
  const overlaps = (c: Candidate): boolean =>
    reserved.some((r) => c.start < r.end && c.end > r.start);

  const found: Candidate[] = [];
  for (const { re, hint } of ANCHORED) found.push(...collect(text, re, "anchored", hint));
  found.push(...collect(text, JWT_RE, "anchored", "jwt"));
  found.push(...collect(text, PEM_RE, "anchored", "private_key"));
  // A: extend KV candidates to the full whitespace-free token so a match can never end
  // inside a credential (see extendKvToToken for the over-capture rationale).
  // A: extend BARE KV candidates to the full whitespace-free token (see extendKvToToken).
  // C: quoted KV candidates keep their whole interior (whitespace included) and are NOT
  // extended — the matching closing quote is already the correct boundary.
  // G: trim stray delimiters from both ends of every KV value, drop if below MIN length.
  const finalize = (c: Candidate, extend: boolean): Candidate | null => finalizeKv(c, text, extend);
  found.push(
    ...collect(text, KV_BARE_RE, "kv").map((c) => finalize(c, true)).filter((c): c is Candidate => c !== null),
    ...collect(text, KV_DQUOTE_RE, "kv").map((c) => finalize(c, false)).filter((c): c is Candidate => c !== null),
    ...collect(text, KV_SQUOTE_RE, "kv").map((c) => finalize(c, false)).filter((c): c is Candidate => c !== null),
  );

  // J: the deny list applies ONLY to entropy candidates. A key that says `token=` is evidence
  // of intent; a bare hex blob is not. So a legacy 40-hex PAT behind `token=` is captured, not
  // dropped for resembling a git SHA.
  const base = dedupe(found).filter(
    (c) => !overlaps(c) && (c.confidence === "entropy" ? !DENY_RE.test(c.value) : true),
  );

  // Bare high-entropy fallback.
  // B: find EVERY occurrence of the token, not just the first (text.indexOf returns only
  // the first index). Keep the reserved-ref and deny filters; check coverage against the
  // wider non-entropy candidates only, so a token appearing twice yields two candidates
  // and applyCapture replaces both.
  const kept: Candidate[] = [...base];
  for (const token of new Set(text.split(/[\s,"'()[\]{}<>=;]+/))) {
    if (!token) continue;
    if (DENY_RE.test(token) || /^(?:https?|file|git|ssh|node):/i.test(token)) continue;
    if (token.includes("/")) continue;
    if (base.some((c) => token.includes(c.value))) continue;
    if (!looksCredentialish(token) || shannonEntropy(token) <= 3.9) continue;
    let idx = text.indexOf(token);
    while (idx !== -1) {
      const cand: Candidate = {
        value: token,
        start: idx,
        end: idx + token.length,
        confidence: "entropy",
      };
      if (!overlaps(cand) && !DENY_RE.test(cand.value)) kept.push(cand);
      idx = text.indexOf(token, idx + token.length);
    }
  }
  return kept.sort((a, b) => a.start - b.start);
}

const CONTEXT_WORDS = [
  "github", "gitlab", "anthropic", "openai", "aws", "azure", "gcp", "slack",
  "staging", "prod", "production", "dev", "qa", "deploy", "docker", "npm",
  "pypi", "huggingface", "database", "db", "redis", "vault", "registry", "sandbox",
];

const ALIAS: Record<string, string> = {
  github: "gh", gitlab: "gl", anthropic: "anthropic", openai: "openai", aws: "aws",
  production: "prod", database: "db", huggingface: "hf", access_key_id: "access_key",
};

function slug(s: string): string {
  return s.toLowerCase().replace(/[^a-z0-9]+/g, "_").replace(/^_+|_+$/g, "");
}

/** D: the text within +/-60 chars of the candidate — names derive from the neighborhood. */
function windowContext(context: string, c: Candidate): string {
  if (c.start < 0 || c.start > context.length) return context;
  const start = Math.max(0, c.start - 60);
  const end = Math.min(context.length, c.end + 60);
  return context.slice(start, end);
}

export function suggestName(candidate: Candidate, context: string, taken: string[]): string {
  // D: name from the candidate's neighborhood, not the whole message. A multi-secret line
  // must not let a later token steer an earlier one's name (e.g. `gh: <ghp_...>  aws: <AKIA>`
  // must not name the GitHub token `gh_aws`). Window +/-60 chars around the candidate.
  const lower = windowContext(context, candidate).toLowerCase();
  const present = CONTEXT_WORDS.filter((w) => lower.includes(w)).map((w) => ALIAS[w] ?? slug(w));
  const hint = candidate.hint ? ALIAS[candidate.hint] ?? slug(candidate.hint).split("_")[0] ?? "" : "";
  const parts = [hint && !present.some((p) => p.startsWith(hint) || hint.startsWith(p)) ? hint : undefined, ...present.slice(0, 2)].filter(
    (p): p is string => Boolean(p),
  );
  let base = parts.filter(Boolean).join("_").slice(0, 58) || "secret";
  if (!isValidName(base)) base = `s_${base}`.slice(0, 64);
  let name = base;
  for (let n = 2; taken.includes(name); n++) name = `${base}-${n}`.slice(0, 64);
  return name;
}

/**
 * Batch naming. One name per candidate, in candidate order, pairwise distinct BY CONSTRUCTION
 * — the caller passes no `taken` and gets no duplicate names. This closes the wrong-credential
 * delivery path: a naive per-candidate `suggestName` with a fresh `taken` named two different
 * secrets `secret`, so `applyCapture` emitted `{{sec:secret}}` twice and `Vault.add` (a UI-
 * confirmed upsert, correct for `/sec add`) silently re-pointed that name at the second value.
 *
 * E: the naming context for candidate `i` is clamped at the neighbouring candidates' spans. A
 * candidate owns the text from the end of the previous candidate up to its OWN end (the last
 * candidate, having no follower, owns the rest of the text). This is deliberate: a fixed radius
 * (the old +/-60) leaks an adjacent secret's label — `gh: <ghp>  aws: <AKIA>`, only six chars
 * apart, still produced `gh_aws` — because adjacent secrets in one paste ARE the realistic
 * capture input, so only neighbour boundaries separate them. Clamping at `nextStart` instead of
 * `ownEnd` would keep the neighbour's label inside this window, so the right boundary stops at
 * the candidate's own span.
 *
 * F: when `existingNameForValue` returns a name for a candidate's value, it is reused unchanged
 * and consumes no counter — spec §4's idempotence rule. Two pastes of one token -> one name;
 * two different tokens -> never one name.
 */
export function suggestNames(
  candidates: Candidate[],
  text: string,
  opts?: { taken?: string[]; existingNameForValue?: (value: string) => string | undefined },
): string[] {
  const seedTaken = opts?.taken ?? [];
  const existingNameForValue = opts?.existingNameForValue;
  // Process in start order so neighbour spans are well defined; aliases (same value) share an index.
  const ordered = [...candidates].map((c, i) => ({ c, i })).sort((a, b) => a.c.start - b.c.start);
  const taken = new Set(seedTaken);

  // I: alias candidates that share a value — one value, one name (also F idempotence:
  // two pastes of one token -> one name). Group by value up front.
  const valueGroups = new Map<string, number[]>(); // value -> ordered candidate indices
  for (const o of ordered) {
    const arr = valueGroups.get(o.c.value) ?? [];
    arr.push(o.i);
    valueGroups.set(o.c.value, arr);
  }

  // I: resolve every reused vault name FIRST, validate it, and seed `taken` with ALL reused
  // names before generating anything. A reused name that is invalid (isValidName fails, e.g.
  // "Bad Name!") is discarded and regenerated — never passed through to a vault write that
  // would throw far from its cause. Aliases share one name, so a value group resolves to a
  // single name.
  const valueName = new Map<string, string>();
  for (const [value] of valueGroups) {
    const existing = existingNameForValue?.(value);
    if (existing !== undefined && isValidName(existing)) {
      valueName.set(value, existing);
      taken.add(existing);
    }
  }

  // Generate for distinct values that have no valid reused name, in start order so a name already
  // chosen for an earlier candidate is in `taken` before a later one is generated.
  for (let k = 0; k < ordered.length; k++) {
    const { c, i } = ordered[k]!;
    if (valueName.has(c.value)) continue; // already resolved (reused or an earlier alias)

    // Clamp the naming context at the neighbours' spans. ctx is the absolute slice
    // [prevEnd, ownEnd) (or [prevEnd, text.length) for the last candidate); `rel` carries the
    // candidate's offsets relative to that slice so suggestName's +/-60 window stays inside it.
    const prevEnd = k > 0 ? ordered[k - 1]!.c.end : 0;
    const ctxEnd = k < ordered.length - 1 ? c.end : text.length;
    const ctx = text.slice(prevEnd, ctxEnd);
    const rel: Candidate = { ...c, start: c.start - prevEnd, end: c.end - prevEnd };
    const name = suggestName(rel, ctx, [...taken]);
    valueName.set(c.value, name);
    taken.add(name);
  }

  // I: final assertion — names bound to DISTINCT values must be pairwise distinct. If two distinct
  // values map to the SAME reused name (a reused name is seeded into `taken`, so generation avoids
  // it, but two distinct values could each resolve to the same reused name), that is exactly the
  // wrong-credential delivery path. Surface it instead of silently collapsing.
  const nameToValue = new Map<string, string>();
  for (const [value, name] of valueName) {
    const prev = nameToValue.get(name);
    if (prev !== undefined && prev !== value) {
      throw new Error(`suggestNames: distinct values would share vault name "${name}"`);
    }
    nameToValue.set(name, value);
  }

  // Map back to candidate order.
  const names = new Array<string>(candidates.length);
  for (const o of ordered) names[o.i] = valueName.get(o.c.value)!;
  return names;
}

export interface CapturedItem {
  candidate: Candidate;
  name: string;
}

/**
 * Replace each candidate with its `{{sec:name}}` ref in a single left-to-right pass. The pairing
 * is taken in the signature (caller passes `{ candidate, name }` pairs), so a caller cannot
 * desynchronise names from candidates the way `() => names.shift()!` structurally could: a queue
 * indexed by call order drifts the moment applyCapture `continue`s without consuming it, silently
 * emitting one secret under another's name.
 *
 * Invariant (preserved for Task 10): `captured` is the ONLY thing wiring should write to the
 * vault. It contains exactly the candidate↔name pairs actually substituted, so `captured` can
 * never hand Vault.add a name that is bound to a different credential than the one written.
 *
 * H: fail closed on a span mismatch. If `text.slice(c.start, c.end)` no longer equals the
 * candidate's stored `value` (e.g. the candidate was captured against an earlier text version and
 * the buffer moved), the candidate is SKIPPED — never rewritten into the output under a possibly
 * wrong name. A silent rewrite here is the root cause of the wrong-credential delivery path.
 */
export function applyCapture(
  text: string,
  items: CapturedItem[],
): { text: string; captured: CapturedItem[] } {
  const captured: CapturedItem[] = [];
  let out = "";
  let cursor = 0;
  for (const { candidate: c, name } of [...items].sort((a, b) => a.candidate.start - b.candidate.start)) {
    if (c.start < cursor) continue; // overlapping / already-covered span
    if (text.slice(c.start, c.end) !== c.value) continue; // H: fail closed on span mismatch
    out += text.slice(cursor, c.start) + `{{sec:${name}}}`;
    cursor = c.end;
    captured.push({ candidate: c, name });
  }
  return { text: out + text.slice(cursor), captured };
}
