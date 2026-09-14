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

// L: re-attach base64 padding that the entropy split set (which includes `=`) stripped off the
// token. See the call site in findCandidates for the full rationale and the unbounded-`=` trap.
function reattachBase64Padding(text: string, raw: string): string {
  const len = raw.length;
  if (len === 0) return raw;
  const pad = (4 - (len % 4)) % 4;
  if (pad === 0 || pad > 2) return raw; // 0 = no padding needed; >2 (i.e. 3) = invalid residue
  let idx = text.indexOf(raw);
  while (idx !== -1) {
    const after = idx + raw.length;
    let eq = 0;
    while (after + eq < text.length && text[after + eq] === "=") eq++;
    if (eq === pad) {
      const next = text[after + eq];
      if (next === undefined || /[\s"',;)\]}]/.test(next)) return raw + "=".repeat(pad);
    }
    idx = text.indexOf(raw, idx + 1);
  }
  return raw;
}

// N/O: post-filters on candidates, keyed on the captured key text / value shape — NOT inside the
// regexes (extendKvToToken rewrites the value after the match, so an in-matcher test would run
// against the wrong string; the matcher is also duplicated across three KV patterns).
//
// N: a `url`-keyed candidate (key text contains "url") captures a plain link only when the value
// is itself credential-bearing: it carries userinfo (`://` with an `@` before the first `/`), its
// host is a known credential-in-URL ingest endpoint, or its query carries a credential parameter.
// Otherwise the link is benign docs/asset prose and must NOT be vaulted (the receipt must not
// claim a credential was found). Webhooks/DSNs behind `url=` are kept; `image_url=`/
// `download_url=`/`url=https://example.com` are dropped.
const KNOWN_CRED_HOSTS = [
  "hooks.slack.com", "api.slack.com", "discord.com", "api.discord.com",
  "events.pagerduty.com", "hooks.pagerduty.com", "grafana.com",
];
const CRED_QUERY_PARAMS = ["sig", "token", "key", "password", "X-Amz-Credential", "X-Amz-Signature"];

function isCredentialUrl(value: string): boolean {
  const m = value.match(/^([a-z][a-z0-9+.-]*):\/\/([^/?#]*)/i);
  if (!m) return false; // not a URL at all -> the caller's other rules decide
  const authority = m[2]!;
  if (authority.includes("@")) return true; // userinfo: real credentials in the URL
  const host = authority.replace(/^[^@]*@/, "").split(":")[0]!.toLowerCase();
  if (KNOWN_CRED_HOSTS.some((h) => host === h || host.endsWith("." + h))) return true;
  const q = value.includes("?") ? value.slice(value.indexOf("?")) : "";
  if (CRED_QUERY_PARAMS.some((p) => new RegExp(`[?&]${p}=`, "i").test(q))) return true;
  return false;
}

function isUrlKeyed(c: Candidate): boolean {
  return /url/i.test(c.hint ?? "");
}

// O: a candidate whose value is a private-key *path* (path stem, or a key-file basename such as
// id_*, *.pem, *.key, *.p12, *.pfx) is NOT a secret to capture here — real key material is Task
// 12's deliberate block. This drops path-shaped values regardless of which keyword fired (e.g.
// `ssh_key=/home/u/.ssh/id_rsa` currently vaults a pathname; it must not).
function isPathValue(value: string): boolean {
  if (/^(\.?\.?\/|~[\/\\]|[A-Za-z]:[\/\\])/.test(value)) return true;
  const base = value.split(/[\/\\]/).pop() ?? "";
  return /^(id_|.*\.(pem|key|p12|pfx))$/i.test(base);
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
  const base = dedupe(found).filter((c) => {
    if (overlaps(c)) return false;
    if (c.confidence === "entropy" && DENY_RE.test(c.value)) return false;
    if (isPathValue(c.value)) return false; // O: private-key paths are not secrets to capture here
    if (isUrlKeyed(c) && !isCredentialUrl(c.value)) return false; // N: plain links behind url-keys
    return true;
  });

  // Bare high-entropy fallback.
  // B: find EVERY occurrence of the token, not just the first (text.indexOf returns only
  // the first index). Keep the reserved-ref and deny filters; check coverage against the
  // wider non-entropy candidates only, so a token appearing twice yields two candidates
  // and applyCapture replaces both.
  const kept: Candidate[] = [...base];
  for (const raw of new Set(text.split(/[\s,"'()[\]{}<>=;]+/))) {
    if (!raw) continue;
    if (DENY_RE.test(raw) || /^(?:https?|file|git|ssh|node):/i.test(raw)) continue;
    // L: re-attach base64 padding the split set stripped. The split set includes `=`, so
    // `dXNlcjpwYXNzd29yZDEyMw==` reached this loop as `dXNlcjpwYXNzd29yZDEyMw` (22 chars — not a
    // multiple of 4, not decodable, a corrupt vault copy). Pad is accepted only when <= 2; a
    // `len % 4 === 1` residue (pad 3) is not valid base64 at all and is left unpadded. An UNBOUNDED
    // `=` run is the corruption in the opposite direction, so we require EXACTLY `pad` `=` followed
    // by a delimiter/end: `key=dXNlcg=x=y` must keep capturing `dXNlcg=x=y` (shell assigns `a=b`),
    // which it does via the KV path below.
    const token = reattachBase64Padding(text, raw);
    // M: replace the old `token.includes("/")` ban (which also banned the base64 alphabet: random
    // bytes average >1 `/` per 22 chars) with a shape test. Reject only a token that STARTS with a
    // scheme or looks like a filesystem path; a bare base64 blob (`CzBVep/E6RM...`) starts with
    // neither, so it is no longer lost.
    if (/^[a-z][a-z0-9+.-]*:\/\//.test(token) || /^(?:\.\.?\/|~[\/\\]|[A-Za-z]:[\/\\])/.test(token)) continue;
    if (base.some((c) => token.includes(c.value))) continue;
    const ent = shannonEntropy(token);
    // A token that is valid base64 (standard or url-safe alphabet) is a credential candidate on its
    // entropy alone — looksCredentialish's own `/^[A-Za-z0-9._/-]+$/ && includes("/") rule rejects
    // base64-with-slash, so without this bypass the entropy fallback would still miss every real
    // blob. scrub.ts is out of scope for this task, so the bypass lives here.
    const base64ish = /^[A-Za-z0-9+/]+=*$/.test(token) || /^[A-Za-z0-9_-]+=?$/.test(token);
    if (token.length < 20 || ent <= 3.9) continue;
    if (!looksCredentialish(token) && !(base64ish && ent > 3.9)) continue;
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

// Q: this single-candidate helper is exported ONLY under a test-only name. `suggestNames` is the
// public batch API; a caller that reaches for the singular helper (the shape that caused Task 6's
// requirement E) could re-introduce the wrong-credential path. Task 10 wiring must use `suggestNames`.
export function suggestNameForTest(candidate: Candidate, context: string, taken: string[]): string {
  // D: name from the candidate's neighborhood, not the whole message. A multi-secret line
  // must not let a later token steer an earlier one's name (e.g. `gh: <ghp_...>  aws: <AKIA>`
  // must not name the GitHub token `gh_aws`). Window +/-60 chars around the candidate.
  const lower = windowContext(context, candidate).toLowerCase();
  // R: prefer the full key hint (not just its first `_`-segment), and suppress context words the
  // hint already represents. e.g. key `DATABASE_URL` / `database_db` already says "database"/"db",
  // so a neighbouring `database`/`db` must not be appended again — that double-counting produced
  // names like `database_db_db`. The suppression is alias-aware (`db` is the alias of `database`),
  // so a hostname such as `db.internal` in the value does not re-introduce a `db` token either.
  const hintSlug = candidate.hint ? (ALIAS[candidate.hint] ?? slug(candidate.hint)) : "";
  const hintAlias = new Set<string>();
  for (const t of hintSlug ? hintSlug.split("_") : []) {
    hintAlias.add(t);
    hintAlias.add(ALIAS[t] ?? t);
  }
  const present = CONTEXT_WORDS
    .filter((w) => lower.includes(w))
    .map((w) => ALIAS[w] ?? slug(w))
    .filter((p) => !hintAlias.has(p) && !hintAlias.has(ALIAS[p] ?? p));
  const hint = hintSlug;
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

  // Distinct values in start order (first occurrence of each value).
  const valuesInOrder: string[] = [];
  for (const o of ordered) {
    if (!valuesInOrder.includes(o.c.value)) valuesInOrder.push(o.c.value);
  }

  // I: resolve the caller's reuse requests. A reused name that is invalid (isValidName fails,
  // e.g. "Bad Name!") is discarded and regenerated. K: when the caller maps SEVERAL DISTINCT
  // values to the SAME reused name (existingNameForValue -> "same" for all 40), that request is
  // unsatisfiable — two different secrets cannot share one vault name. Degrade it: keep the name
  // for the first value (start order) and drop the reuse for the rest, so they are generated as
  // distinct valid names instead of throwing and costing the user their message. The caller's
  // reuse keeps priority over generated names (seeded into `taken` first), matching requirement I.
  const desiredReuse = new Map<string, string>(); // value -> valid reused name (pre-collision)
  for (const value of valuesInOrder) {
    const existing = existingNameForValue?.(value);
    if (existing !== undefined && isValidName(existing)) desiredReuse.set(value, existing);
  }

  // Keep a reused name for the first (start-order) value that requests it; degrade later collisions.
  const reuseOwner = new Map<string, string>(); // reusedName -> owning value
  const valueName = new Map<string, string>(); // value -> resolved name
  for (const value of valuesInOrder) {
    const name = desiredReuse.get(value);
    if (name === undefined) continue;
    if (!reuseOwner.has(name)) {
      reuseOwner.set(name, value);
      valueName.set(value, name);
      taken.add(name); // seed before generation so generated names avoid the caller's reuse
    }
    // else: a distinct value already owns this reused name -> degrade (drop reuse, generate later)
  }

  // Generate for distinct values without a kept reused name, in start order so a name already
  // chosen for an earlier candidate is in `taken` before a later one is generated.
  for (let k = 0; k < ordered.length; k++) {
    const { c, i } = ordered[k]!;
    if (valueName.has(c.value)) continue; // already resolved (kept reuse or earlier alias)

    // Clamp the naming context at the neighbours' spans. ctx is the absolute slice
    // [prevEnd, ownEnd) (or [prevEnd, text.length) for the last candidate); `rel` carries the
    // candidate's offsets relative to that slice so suggestNameForTest's +/-60 window stays inside it.
    const prevEnd = k > 0 ? ordered[k - 1]!.c.end : 0;
    const ctxEnd = k < ordered.length - 1 ? c.end : text.length;
    const ctx = text.slice(prevEnd, ctxEnd);
    const rel: Candidate = { ...c, start: c.start - prevEnd, end: c.end - prevEnd };
    const name = suggestNameForTest(rel, ctx, [...taken]);
    valueName.set(c.value, name);
    taken.add(name);
  }

  // I/K invariant: a name must never bind two DISTINCT values. The module's own generation avoids
  // `taken` (every kept reuse name is seeded into it before generation), so a remaining collision
  // is a genuine internal bug the caller could not have caused — surface it rather than collapse.
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
 *
 * P: a vault name must bind exactly one value. `CapturedItem[]` is an exported interface a caller
 * can hand-build, so a list that assigns one name to two distinct values re-opens the exact
 * wrong-credential path `suggestNames` documents closing. We assert pairwise (name → value)
 * consistency up front and SKIP the violating items rather than writing one name for two
 * credentials. Skips are counted (see `skipped`) so a receipt cannot overstate what was protected
 * by counting `items.length` — measured: two items with one stale span yield `captured.length === 1`.
 */
export function applyCapture(
  text: string,
  items: CapturedItem[],
): { text: string; captured: CapturedItem[]; skipped: number } {
  const captured: CapturedItem[] = [];
  let skipped = 0;
  let out = "";
  let cursor = 0;
  const sorted = [...items].sort((a, b) => a.candidate.start - b.candidate.start);
  // P: bind each name to exactly one value; a name already bound to a different value is a conflict
  // and the later (start-order) item carrying it is skipped.
  const nameToValue = new Map<string, string>();
  const skip = new Set<CapturedItem>();
  for (const item of sorted) {
    const prev = nameToValue.get(item.name);
    if (prev !== undefined && prev !== item.candidate.value) skip.add(item);
    else nameToValue.set(item.name, item.candidate.value);
  }
  for (const item of sorted) {
    if (skip.has(item)) { skipped++; continue; }
    const { candidate: c, name } = item;
    if (c.start < cursor) { skipped++; continue; } // overlapping / already-covered span
    if (text.slice(c.start, c.end) !== c.value) { skipped++; continue; } // H: fail closed on span mismatch
    out += text.slice(cursor, c.start) + `{{sec:${name}}}`;
    cursor = c.end;
    captured.push({ candidate: c, name });
  }
  return { text: out + text.slice(cursor), captured, skipped };
}
