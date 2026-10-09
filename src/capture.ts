import { findRefs } from "./substitute.ts";
import { isValidName, MIN_SCRUBABLE_LENGTH } from "./refs.ts";
import {
  IDENTIFIER_WORD_RATIO,
  PROVIDER_PREFIXES,
  isPlaceholderValue,
  looksCredentialish,
  looksLikeIdentifierText,
  looksLikeSecretReference,
  shannonEntropy,
} from "./entropy.ts";

export type Confidence = "anchored" | "kv" | "entropy";

export interface Candidate {
  value: string;
  start: number;
  end: number;
  confidence: Confidence;
  hint?: string;
  /**
   * Why this candidate was raised, in words a person can argue with.
   *
   * It exists because of a receipt that said only `sec:secret · len 21`: three
   * ordinary-looking runs from a Chinese expense prompt were rewritten into refs, the
   * user had no way to tell a shape guess from a keyword hit, and by the time the model
   * complained the original sentence was already gone. The confirm dialog and the receipt
   * both render this, so a wrong guess is visible BEFORE it costs anything.
   */
  evidence?: string;
}

// Tier 1 is derived from the shared provider table rather than restated: capture needs
// the hint, and the scrubber needs the pattern, and two copies of one list is how
// `sk-proj-…` ended up recognised by everything except the thing that rewrites prompts.
const ANCHORED: Array<{ re: RegExp; hint: string }> = [
  ...PROVIDER_PREFIXES.map((p) => ({ re: new RegExp(p.source, "g"), hint: p.hint })),
];

const JWT_RE = /eyJ[A-Za-z0-9_\-]{5,}\.eyJ[A-Za-z0-9_\-]{5,}\.[A-Za-z0-9_\-]{8,}/g;
const PEM_RE = /-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z0-9 ]*PRIVATE KEY-----/g;
/**
 * A private key pasted TRUNCATED — no END line, because the paste stopped.
 *
 * Before this, a half-pasted key produced no anchored candidate at all and survived only
 * if the base64 body happened to clear the entropy floor, which is the least reliable way
 * to protect a private key. The body is bounded to a real base64/whitespace run so this
 * cannot swallow the rest of the prompt. It is collected BEFORE the whole-block rule so a
 * truncated paste is never also treated as a PEM region whose interior is excluded.
 */
const PEM_TRUNCATED_RE = /-{5}BEGIN [A-Z0-9 ]*PRIVATE KEY-{5}[A-Za-z0-9+/=\r\n ]{64,4096}/g;
/**
 * How short a value may be and still count, decided by the keyword next to it.
 *
 * One flat floor of 8 was wrong in both directions at once: it dropped a 7-character
 * password behind a strong `DB_PASSWORD=` key (the one place a user is certain it IS a
 * password), and it invited a class of false positives we then filtered one shape at a
 * time. A keyword that says "password" needs almost no corroboration; a keyword that says
 * "token" or "key" does, because those words also head cache keys, ids and config.
 */
const STRONG_KEYWORD_RE = /pass|pwd|passphrase|secret|private|credential|密码|口令|密钥|秘钥|私钥/i;
const MIN_STRONG_VALUE_LENGTH = 3;

/** Optional type annotation between keyword and separator, e.g. `str`, `Optional[str]`. */
const TYPE_ANNOTATION = String.raw`["'\x60]?[ \t]*:[ \t]*[A-Za-z_][\w.\[\]| ]{0,40}?[ \t]*`;
/** The keyword, then `=`. */
const KV_ASSIGN = String.raw`["'\x60]?(?:${TYPE_ANNOTATION})?[ \t]*(?::=|=>|=)[ \t]*`;
/** The keyword, then `:` — JSON, YAML, HTTP headers. */
const KV_COLON = String.raw`["'\x60]?[ \t]*:[ \t]*`;

/**
 * The keyword, at a SEGMENT boundary, so `my_key=` matches while `monkey=`, `turnkey=` and
 * `keyboard=` do not. Kept as a source string because four rules share it now and a
 * divergence between them would be invisible.
 */
const KV_KEYWORD_SOURCE = String.raw`([A-Za-z0-9_\-]*(?<![A-Za-z0-9])(?:token|secret|password|passwd|pwd|api[_-]?key|authorization|access[_-]?key|credential|cred|url|auth|key)(?![A-Za-z0-9_-])[A-Za-z0-9_\-]*)`;

// A: the BARE value stops at whitespace and quotes and deliberately ALLOWS `&` and `\`,
// because excluding them leaked a credential's tail in the clear.
// C: a QUOTED value captures its interior whole (whitespace included); the closing quote is
// already the correct boundary, so a quoted value is never extended.
const KV_BARE_RE = new RegExp(`${KV_KEYWORD_SOURCE}(?:${KV_ASSIGN}|${KV_COLON})([^\\s"'<>]{3,})`, "gi");
const KV_DQUOTE_RE = new RegExp(`${KV_KEYWORD_SOURCE}(?:${KV_ASSIGN}|${KV_COLON})\\\\?"([^"\\\\]{3,}?)\\\\?"`, "gi");
const KV_SQUOTE_RE = new RegExp(`${KV_KEYWORD_SOURCE}(?:${KV_ASSIGN}|${KV_COLON})\\\\?'([^'\\\\]{3,}?)\\\\?'`, "gi");

/**
 * `--password hunter22`, and the equals form of the same.
 *
 * The space-separated form has no `=` for the assignment rules to find, so this shape
 * walked straight past capture: measured, `mysql --password hunter22 -h host` was missed.
 */
const KV_FLAG_RE =
  /(?<![\w-])--?(password|passwd|pwd|pass|secret|token|api-?key|access-?key|auth-?token|authorization)(?:=|[ \t]+)["']?([^\s"'\n]{3,})/gi;

/**
 * Chinese: a password word followed by a colon, an equals, or one of the verbs
 * 是 / 为 / 设为 / 改为 that carry the same meaning.
 *
 * The keyword list above is ASCII, so a Chinese prompt had no recognised way to say
 * "password" — measured misses on a bare colon form and on a full sentence containing one.
 * These forms also use full-width punctuation, which the value class must tolerate.
 */
const KV_CJK_RE =
  /(密码|口令|密钥|秘钥|令牌|私钥)(?:[ \t]*(?:是|为|叫|设为|设置为|改为|改成|修改为)[ \t]*|[ \t]*[:：=][ \t]*)["'“‘「]?([\x21-\x7E]{3,})/g;

/**
 * English prose: `my password is Tr0ub4dor&3`.
 *
 * Its validator is the reason this rule cannot chew a sentence: a value with no digit, no
 * symbol and no case change is prose, so `the password is incorrect` stays untouched.
 */
const KV_PROSE_RE =
  /\b(password|passwd|passcode|passphrase|secret|api[ _-]?key|token)\b[ \t]+(?:is|was)(?:[ \t]*:[ \t]*|[ \t]+)["'“‘]?([^\s"'”’,;]{4,})/gi;

/**
 * Basic auth on a command line: `curl -u admin:p@ssw0rd`.
 *
 * Only the PASSWORD half is captured. A username is not a credential, and storing the
 * whole pair buys nothing the user cannot already read off their own screen.
 */
const BASIC_AUTH_RE = /(?<![\w-])(?:-u|--user)[ \t]+['"]?[^\s:'"]+:["']?([^\s'"]{3,})/g;

const DENY_RE =
  /^[0-9a-f]{7}$|^[0-9a-f]{40}$|^[0-9a-f]{64}$|^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/**
 * The rules that need a key text beside the value, with the per-rule verdict on it.
 *
 * `validate` is where each rule states what its own value must look like, because the
 * shapes are not interchangeable: a prose value needs a digit or symbol to be a secret,
 * and every value everywhere needs the placeholder and reference vetoes.
 */
interface KvRule {
  re: RegExp;
  /** Fixed hint for rules with no key text of their own. */
  hint?: string;
  /** Group index of the value. Defaults to 2, which every rule here keeps. */
  valueIndex?: number;
  validate?: (value: string, key: string) => boolean;
}

/** True for a value that is a template, a type name, an env lookup or a call. */
function isVetoedValue(value: string): boolean {
  return isPlaceholderValue(value) || looksLikeSecretReference(value);
}

/** The keyword decides how much corroboration the value needs. */
function valueLengthOk(value: string, key: string): boolean {
  const floor = STRONG_KEYWORD_RE.test(key) ? MIN_STRONG_VALUE_LENGTH : MIN_SCRUBABLE_LENGTH;
  return value.length >= floor;
}

const KV_RULES: KvRule[] = [
  { re: KV_BARE_RE },
  { re: KV_DQUOTE_RE },
  { re: KV_SQUOTE_RE },
  { re: KV_FLAG_RE },
  { re: KV_CJK_RE },
  {
    re: KV_PROSE_RE,
    validate: (value) => {
      if (isVetoedValue(value)) return false;
      return /\d/.test(value) || /[^A-Za-z0-9]/.test(value) || (/[a-z]/.test(value) && /[A-Z]/.test(value));
    },
  },
  { re: BASIC_AUTH_RE, hint: "basic_auth", valueIndex: 1 },
];

function collect(text: string, re: RegExp, confidence: Confidence, hint?: string, valueIndex = 0): Candidate[] {
  const out: Candidate[] = [];
  re.lastIndex = 0;
  let m: RegExpExecArray | null;
  while ((m = re.exec(text))) {
    const value = confidence === "kv" ? (m[valueIndex === 0 ? 2 : valueIndex] as string) : (m[0] as string);
    if (!value) continue;
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

/** One KV rule's candidates: validate, then extend/trim, then apply the length floor. */
function collectKv(text: string, rule: KvRule, extend: boolean): Candidate[] {
  const valueIndex = rule.valueIndex ?? 2;
  return collect(text, rule.re, "kv", rule.hint, valueIndex)
    .map((c) => finalizeKv(c, text, extend))
    .filter((c) => {
      const key = c.hint ?? "";
      if (isVetoedValue(c.value)) return false;
      if (rule.validate && !rule.validate(c.value, key)) return false;
      return valueLengthOk(c.value, key);
    });
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
function finalizeKv(c: Candidate, text: string, extend: boolean): Candidate {
  let cand = c;
  if (extend) cand = extendKvToToken(cand, text);
  const t = trimDelimiters(cand.value);
  // The length floor is NOT applied here. It used to be a flat 8, applied before the
  // keyword was consulted, which meant a 7-character password behind a strong key was
  // dropped here and never reached the per-keyword floor in collectKv. A candidate of
  // zero length is the only thing this can still refuse.
  if (t.value.length === 0) return { ...cand, value: "", start: cand.start, end: cand.start };
  return { ...cand, value: t.value, start: cand.start + t.left, end: cand.end - t.right };
}

// L: re-attach base64 padding that the entropy split set (which includes `=`) stripped off the
// token. See the call site in findCandidates for the full rationale and the unbounded-`=` trap.
// V(c): padding is re-attached PER OCCURRENCE (anchored to `idx`), not via a global indexOf, so a
// padded occurrence cannot supply padding to a different occurrence of the same raw that has none.
function reattachBase64PaddingAt(text: string, raw: string, idx: number): string {
  const len = raw.length;
  if (len === 0) return raw;
  const pad = (4 - (len % 4)) % 4;
  if (pad === 0 || pad > 2) return raw; // 0 = no padding needed; >2 (i.e. 3) = invalid residue
  const after = idx + raw.length;
  let eq = 0;
  while (after + eq < text.length && text[after + eq] === "=") eq++;
  if (eq === pad) {
    const next = text[after + eq];
    if (next === undefined || /[\s"',;)\]}]/.test(next)) return raw + "=".repeat(pad);
  }
  return raw;
}

// N/O: post-filters on candidates, keyed on the captured key text / value shape — NOT inside the
// regexes (extendKvToToken rewrites the value after the match, so an in-matcher test would run
// against the wrong string; the matcher is also duplicated across three KV patterns).
//
// N: a `url`-keyed candidate (key text contains "url") captures a plain link only when the value
// is itself credential-bearing: it carries userinfo (`://` with an `@` before the first `/`), its
// host is a known credential-in-URL ingest endpoint AND the path matches the ingest prefix, or its
// query carries a credential parameter. Otherwise the link is benign docs/asset prose and must NOT
// be vaulted (the receipt must not claim a credential was found). Webhooks/DSNs behind `url=` are
// kept; `image_url=`/`download_url=`/`url=https://example.com` are dropped.
//
// U: the host allow-list requires a PATH PREFIX for every entry — a bare host match produces false
// positives (the secret rides in headers / basic auth / the query, which the userinfo and query arms
// already cover). Hosts whose secrets never ride in the path (`api.slack.com`, `grafana.com`, etc.)
// were deleted. `ingest.sentry.io` requires a numeric project path; `datadoghq.com` / `grafana.net`
// require one of their ingest prefixes. No entropy test is used in the gate.
const CRED_HOST_PATHS: Array<{ host: string; suffix?: boolean; paths: string[] }> = [
  { host: "hooks.slack.com", paths: ["/services/", "/hooks/", "/tokens/"] },
  { host: "discord.com", paths: ["/api/webhooks/"] },
  { host: "discordapp.com", paths: ["/api/webhooks/"] },
  { host: "events.pagerduty.com", paths: ["/v2/enqueue", "/integration/"] },
  { host: "hooks.pagerduty.com", paths: ["/v2/enqueue", "/integration/"] },
  { host: "grafana.net", suffix: true, paths: ["/collect/", "/otlp", "/loki/api/1/push", "/loki/api/v1/push", "/instances/"] },
  { host: "ingest.sentry.io", suffix: true, paths: [] }, // numeric project path handled below
  { host: "datadoghq.com", suffix: true, paths: ["/api/v2/logs", "/v1/input/", "/lambda/functions/"] },
];
const CRED_QUERY_PARAMS = ["sig", "token", "key", "password", "X-Amz-Credential", "X-Amz-Signature"];

function isCredentialUrl(value: string): boolean {
  const m = value.match(/^([a-z][a-z0-9+.-]*):\/\/([^/?#]*)((?:\/[^?#]*)?)/i);
  if (!m) return false; // not a URL at all -> the caller's other rules decide
  const authority = m[2]!;
  if (authority.includes("@")) return true; // userinfo: real credentials in the URL
  const host = authority.replace(/^[^@]*@/, "").split(":")[0]!.toLowerCase();
  const path = (m[3] ?? "").toLowerCase();
  for (const rule of CRED_HOST_PATHS) {
    const hostOk = rule.suffix
      ? host === rule.host || host.endsWith("." + rule.host)
      : host === rule.host;
    if (!hostOk) continue;
    if (rule.host === "ingest.sentry.io") {
      // Sentry ingest: only a numeric project id path is credential-bearing.
      if (/^\/\d/.test(path)) return true;
      continue;
    }
    if (rule.paths.length === 0) return true;
    if (rule.paths.some((p) => path.startsWith(p))) return true;
  }
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

// T: structural exclusions for the entropy path so M's base64 accept does not vault public material.
// (a) a token whose span falls STRICTLY INSIDE a `-----BEGIN …-----` … `-----END …-----` region is
// the body of some PEM block — not a secret to capture here (a public key, a cert, a CSR, etc.). We
// exclude it as a REGION, not by peeking at the ~24 chars before each token: a public-key body is
// several base64 lines, and only its FIRST line is preceded by the BEGIN header, so a neighbour check
// would still vault every later line. The PRIVATE KEY block is preserved because the anchored PEM
// collector captures it WHOLE (its candidate spans the region boundaries: start === BEGIN, end ===
// after END), so it is never strictly interior. (b) a token that is the payload of a `data:…;base64`
// URI in the same whitespace-free run is an embedded asset, not a secret.
function pemRegions(text: string): Array<{ start: number; end: number }> {
  const out: Array<{ start: number; end: number }> = [];
  const re = /-----BEGIN [A-Z0-9 ]*-----[\s\S]*?-----END [A-Z0-9 ]*-----/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(text))) out.push({ start: m.index, end: m.index + m[0].length });
  return out;
}
// T(a): true when the candidate sits strictly inside a PEM region (after the BEGIN line, at or before
// the END line). A whole-block anchored candidate (start===region.start, end===region.end) is NOT
// interior and so survives.
function inPemRegion(c: Candidate, regions: Array<{ start: number; end: number }>): boolean {
  return regions.some((r) => c.start > r.start && c.end <= r.end);
}
// (b) a token that is the payload of a `data:…;base64` URI in the same whitespace-free run is an
// embedded asset (e.g. a pasted screenshot), not a secret to vault.
function isDataUriPayload(text: string, idx: number): boolean {
  let runStart = idx;
  while (runStart > 0 && !/\s/.test(text[runStart - 1]!)) runStart--;
  const runBefore = text.slice(runStart, idx);
  return /^data:[^\s]*;base64,?$/i.test(runBefore);
}

export function findCandidates(text: string): Candidate[] {
  if (!text.trim()) return [];
  const reserved: Array<{ start: number; end: number }> = findRefs(text).map((r) => ({
    start: r.start,
    end: r.end,
  }));
  const overlaps = (c: Candidate): boolean =>
    reserved.some((r) => c.start < r.end && c.end > r.start);
  // T(a): PEM regions — once computed, ANY candidate strictly inside one is a PEM-body line and is
  // excluded regardless of how it was found. The anchored PRIVATE KEY collector's candidate spans
  // the region boundary, so it is not interior and is kept whole.
  const pem = pemRegions(text);
  const inPem = (c: Candidate): boolean => inPemRegion(c, pem);

  const found: Candidate[] = [];
  for (const { re, hint } of ANCHORED) found.push(...collect(text, re, "anchored", hint));
  found.push(...collect(text, JWT_RE, "anchored", "jwt"));
  found.push(...collect(text, PEM_RE, "anchored", "private_key"));
  // A truncated paste has no END line, so the whole-block rule above cannot see it. It is
  // collected first so that dedupe keeps whichever is wider when a block is complete.
  found.push(...collect(text, PEM_TRUNCATED_RE, "anchored", "private_key"));
  // A: extend BARE KV candidates to the full whitespace-free token so a match can never end
  // inside a credential (see extendKvToToken for the over-capture rationale). C: a quoted
  // value keeps its whole interior and is NOT extended — the closing quote is its boundary.
  // G: trim stray delimiters from both ends of every KV value.
  for (const rule of KV_RULES) found.push(...collectKv(text, rule, rule.re === KV_BARE_RE));

  // J: the deny list applies ONLY to entropy candidates. A key that says `token=` is evidence
  // of intent; a bare hex blob is not. So a legacy 40-hex PAT behind `token=` is captured, not
  // dropped for resembling a git SHA.
  const base = dedupe(found).filter((c) => {
    if (overlaps(c)) return false;
    if (c.confidence === "entropy" && DENY_RE.test(c.value)) return false;
    if (isPathValue(c.value)) return false; // O: private-key paths are not secrets to capture here
    if (isUrlKeyed(c) && !isCredentialUrl(c.value)) return false; // N: plain links behind url-keys
    if (inPem(c)) return false; // T(a): interior PEM-body lines (public keys, certs, ...) are not secrets
    return true;
  });

  // Bare high-entropy fallback.
  // B: find EVERY occurrence of the token, not just the first (text.indexOf returns only
  // the first index). Keep the reserved-ref and deny filters; check coverage against the
  // wider non-entropy candidates only, so a token appearing twice yields two candidates
  // and applyCapture replaces both.
  //
  // S: a scheme-prefixed token is run through the credential-URL test too — a bare DSN or webhook
  // pasted WITHOUT a `url=` key (`migrate with https://user:pass@db...`, `postgres://user:pass@...`)
  // is exactly as secret as `DATABASE_URL=<dsn>` and must not be missed just because it lacks a key.
  // T: PEM bodies and data-URI payloads are excluded structurally (not by entropy).
  const kept: Candidate[] = [...base];
  const pushEntropy = (token: string, idx: number): void => {
    const ent = shannonEntropy(token);
    const cand: Candidate = {
      value: token,
      start: idx,
      end: idx + token.length,
      confidence: "entropy",
      // The evidence a person needs in order to disagree with us, and the whole reason a
      // guess can be confirmed before it costs anything: every field here is a reason we
      // think this is a secret and NOTHING about it says so.
      evidence:
        `no keyword near it · ${ent.toFixed(2)} bits/char · len ${token.length} · ` +
        `${/[^\x20-\x7E]/.test(token) ? "non-ascii" : "ascii"} · ` +
        `${/[0-9]/.test(token) ? "has digit" : "no digit"} · guess only`,
    };
    if (overlaps(cand) || DENY_RE.test(cand.value)) return;
    if (inPem(cand) || isDataUriPayload(text, idx)) return; // T: PEM body lines and data-URI payloads
    if (isPlaceholderValue(cand.value) || looksLikeSecretReference(cand.value)) return;
    kept.push(cand);
  };
  for (const raw of new Set(text.split(/[\s,"'()[\]{}<>=;]+/))) {
    if (!raw) continue;
    if (DENY_RE.test(raw)) continue;
    let idx = text.indexOf(raw);
    while (idx !== -1) {
      // V(c): re-attach padding for THIS occurrence so a padded occurrence cannot supply padding
      // to an unpadded one of the same raw.
      const token = reattachBase64PaddingAt(text, raw, idx);
      if (base.some((c) => token.includes(c.value) || c.value.includes(token))) { idx = text.indexOf(raw, idx + raw.length); continue; }
      // S: scheme-prefixed token — capture only if credential-bearing (userinfo / cred query);
      // benign scheme links stay skipped.
      if (/^[a-z][a-z0-9+.-]*:\/\//.test(token)) {
        if (isCredentialUrl(token)) pushEntropy(token, idx);
        idx = text.indexOf(raw, idx + raw.length);
        continue;
      }
      // remaining non-// scheme forms (file:, git:, ssh:, node:) are not credentials here
      if (/^(?:https?|file|git|ssh|node):/i.test(token)) { idx = text.indexOf(raw, idx + raw.length); continue; }
      // M: replace the old `token.includes("/")` ban (which also banned the base64 alphabet: random
      // bytes average >1 `/` per 22 chars) with a shape test. Reject only a token that STARTS with a
      // filesystem path stem; a bare base64 blob (`CzBVep/E6RM...`) starts with neither, so it is no
      // longer lost.
      if (/^(?:\.\.?\/|~[\/\\]|[A-Za-z]:[\/\\])/.test(token)) { idx = text.indexOf(raw, idx + raw.length); continue; }
      const ent = shannonEntropy(token);
      // A token that is valid base64 (standard or url-safe alphabet) is a credential candidate on its
      // entropy alone — looksCredentialish's own `/^[A-Za-z0-9._/-]+$/ && includes("/") rule rejects
      // base64-with-slash, so without this bypass the entropy fallback would still miss every real
      // blob. scrub.ts is out of scope for this task, so the bypass lives here.
      const base64ish = /^[A-Za-z0-9+/]+=*$/.test(token) || /^[A-Za-z0-9_-]+=?$/.test(token);
      if (token.length < 20 || ent <= 3.9) { idx = text.indexOf(raw, idx + raw.length); continue; }
      if (!looksCredentialish(token) && !(base64ish && ent > 3.9)) { idx = text.indexOf(raw, idx + raw.length); continue; }
      // The three gates added on 2026-10-09, each answering a measured false positive.
      //
      // 1. ASCII only. A Chinese prompt has no spaces, so its runs are long, and Shannon
      //    entropy rewards them: Chinese characters barely repeat, so the same length of
      //    Chinese scores ~0.4 bits/char HIGHER than Latin. Measured on the real capture,
      //    `保持bitbucket和lightnode不变，` scored 4.14 and was rewritten into a ref — with one
      //    Latin brand name in it, which is what supplied the second character class that
      //    looksCredentialish requires. A real pasted credential that contains non-ASCII is
      //    vanishingly rare next to how often ordinary Chinese prose reaches this line.
      if (/[^\x20-\x7E]/.test(token)) { idx = text.indexOf(raw, idx + raw.length); continue; }
      // 2. Not built out of words. `NewPaymentCaseReconcilerFromContext` scored 4.14 bits/char
      //    — HIGHER than the secret it was mistaken for — so entropy was never going to
      //    separate them. Structure does: names are word runs, random bytes are not.
      if (looksLikeIdentifierText(token)) { idx = text.indexOf(raw, idx + raw.length); continue; }
      // 3. Shape rules that separate a random token from a CONSTANT. Written as four
      //    small tests rather than "must have lower, upper and a digit", because that
      //    blunter form was measured losing a real secret: a 29-character all-lowercase
      //    token with digits is an ordinary base64 blob, and it has no uppercase at all.
      //    What actually identifies a constant is that it has no digits, or is hex.
      if (/^[0-9a-f]+$/i.test(token)) { idx = text.indexOf(raw, idx + raw.length); continue; }
      if (!/[a-z]/.test(token) && !/[0-9]/.test(token)) {
        idx = text.indexOf(raw, idx + raw.length); // ALL-CAPS word, e.g. an env var name
        continue;
      }
      // 4. A snake/kebab CONSTANT: no digits anywhere, and every segment a plain word.
      //    The no-digits half is load-bearing. Without it the rule also eats
      //    `sk-proj-<random>`, whose first two segments are pure letters — the exact
      //    misfire that made the third-party detector's version of this rule unusable.
      if (!/[0-9]/.test(token)) {
        const segs = token.split(/[_-]/).filter(Boolean);
        if (segs.length >= 3 && segs.every((s) => /^[A-Za-z]{2,}$/.test(s))) {
          idx = text.indexOf(raw, idx + raw.length);
          continue;
        }
      }
      pushEntropy(token, idx);
      idx = text.indexOf(raw, idx + raw.length);
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
  // W: match context words on WORD boundaries, not as bare substrings — `lower.includes("aws")`
  // fired inside "laws" and `dev` inside "development", drifting names between drafts of the same
  // paste. A context word must appear as its own word (e.g. surrounded by non-word chars / boundaries).
  const present = CONTEXT_WORDS
    .filter((w) => new RegExp(`\\b${w}\\b`).test(lower))
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
): { text: string; captured: CapturedItem[]; skipped: { nameConflict: number; staleSpan: number } } {
  const captured: CapturedItem[] = [];
  let nameConflicts = 0;
  let staleSpans = 0;
  let out = "";
  let cursor = 0;
  // V(a): sort by start, then by END (widest last) so two candidates sharing a start offset (a KV
  // match and an entropy match at the same position) are settled deterministically, not by caller
  // order — matching what `dedupe` already does for the find side.
  const sorted = [...items].sort(
    (a, b) => a.candidate.start - b.candidate.start || b.candidate.end - a.candidate.end,
  );
  // P: bind each name to exactly one value; a name already bound to a different value is a conflict
  // and the later (start-order) item carrying it is skipped. V(b): this is a *name conflict* (a wiring
  // bug) and is reported separately from a *stale span* (the buffer moved) so a receipt can tell the
  // two apart instead of a single opaque `skipped` count.
  const nameToValue = new Map<string, string>();
  const skipNameConflict = new Set<CapturedItem>();
  for (const item of sorted) {
    const prev = nameToValue.get(item.name);
    if (prev !== undefined && prev !== item.candidate.value) skipNameConflict.add(item);
    else nameToValue.set(item.name, item.candidate.value);
  }
  for (const item of sorted) {
    if (skipNameConflict.has(item)) { nameConflicts++; continue; }
    const { candidate: c, name } = item;
    if (c.start < cursor) { staleSpans++; continue; } // overlapping / already-covered span
    if (text.slice(c.start, c.end) !== c.value) { staleSpans++; continue; } // H: fail closed on span mismatch
    out += text.slice(cursor, c.start) + `{{sec:${name}}}`;
    cursor = c.end;
    captured.push({ candidate: c, name });
  }
  return { text: out + text.slice(cursor), captured, skipped: { nameConflict: nameConflicts, staleSpan: staleSpans } };
}
