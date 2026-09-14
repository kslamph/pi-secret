import { findRefs } from "./substitute.ts";
import { isValidName } from "./refs.ts";
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
// A: KV value classes. The BARE form (below) stops at whitespace and quotes and
// deliberately ALLOWS `&` and `\` to match Task 5's scrub class; excluding them leaked a tail
// in the clear. C: the QUOTED forms capture the interior of `="..."` / `='...'` whole
// (whitespace included) to the matching closing quote. A quoted value is NOT extended by A
// (the interior is already whole); an UNCLOSED quote matches neither form and yields no
// candidate.
const KV_BARE_RE =
  /([A-Za-z0-9_\-]*(?:token|secret|password|passwd|pwd|api[_-]?key|authorization|access[_-]?key)[A-Za-z0-9_\-]*)["']?\s*[=:]\s*([^\s"'<>]{8,})/gi;
const KV_DQUOTE_RE =
  /([A-Za-z0-9_\-]*(?:token|secret|password|passwd|pwd|api[_-]?key|authorization|access[_-]?key)[A-Za-z0-9_\-]*)["']?\s*[=:]\s*"([^"]{8,}?)"/gi;
const KV_SQUOTE_RE =
  /([A-Za-z0-9_\-]*(?:token|secret|password|passwd|pwd|api[_-]?key|authorization|access[_-]?key)[A-Za-z0-9_\-]*)["']?\s*[=:]\s*'([^']{8,}?)'/gi;

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
  found.push(...collect(text, KV_BARE_RE, "kv").map((c) => extendKvToToken(c, text)));
  found.push(...collect(text, KV_DQUOTE_RE, "kv"));
  found.push(...collect(text, KV_SQUOTE_RE, "kv"));

  const base = dedupe(found).filter((c) => !overlaps(c) && !DENY_RE.test(c.value));

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
      if (!overlaps(cand)) kept.push(cand);
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

export function applyCapture(
  text: string,
  candidates: Candidate[],
  nameFor: (c: Candidate) => string,
): { text: string; captured: Array<{ candidate: Candidate; name: string }> } {
  const captured: Array<{ candidate: Candidate; name: string }> = [];
  let out = "";
  let cursor = 0;
  for (const c of [...candidates].sort((a, b) => a.start - b.start)) {
    if (c.start < cursor) continue;
    const name = nameFor(c);
    out += text.slice(cursor, c.start) + `{{sec:${name}}}`;
    cursor = c.end;
    captured.push({ candidate: c, name });
  }
  return { text: out + text.slice(cursor), captured };
}
