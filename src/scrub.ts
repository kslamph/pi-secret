import { MIN_SCRUBABLE_LENGTH, derivedForms } from "./refs.ts";

export interface SecretProvider {
  values(): string[];
  findByValue(value: string): { name: string } | undefined;
}

export interface ScrubOptions {
  /** Shape masking. Default true. Disable for file-content reads to avoid corrupting write-back. */
  shapes?: boolean;
}

export interface ScrubResult {
  text: string;
  hits: number;
}

const GENERIC = "{{sec:redacted}}";

/**
 * Anchored provider formats, most specific prefix first so `dckr_pat_` wins over
 * `pat_`-like forms and `sk-ant-` wins over `sk-`.
 *
 * Built as an array of single-line sources joined with `|`, and NOT as a
 * multi-line String.raw template. A template literal here embeds real newlines and
 * indentation into the pattern, so `(?:\n  dckr_pat_…` would demand a newline before
 * every token and match nothing — a silent, total failure of shape scrubbing. There
 * is no `x` (verbose) flag in this V8 to make the readable form work:
 * `new RegExp(src, "gx")` throws SyntaxError at module load.
 */
const PREFIX_SOURCES = [
  "dckr_pat_[A-Za-z0-9_\\-]{20,}",
  "github_pat_[A-Za-z0-9_]{20,}",
  "gh[pousr]_[A-Za-z0-9]{20,}",
  "sk-ant-[A-Za-z0-9_\\-]{20,}",
  "sk-[A-Za-z0-9]{20,}",
  "AIza[0-9A-Za-z_\\-]{30,}",
  "(?:AKIA|ASIA)[0-9A-Z]{16}",
  "xox[baprs]-[A-Za-z0-9\\-]{10,}",
  "glpat-[A-Za-z0-9_\\-]{20,}",
  "npm_[A-Za-z0-9]{30,}",
  "pypi-Po-[A-Za-z0-9]{20,}",
  "hf_[A-Za-z0-9]{20,}",
];
const PREFIX_RE = `(?:${PREFIX_SOURCES.join("|")})`;

const PEM_RE = String.raw`-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z0-9 ]*PRIVATE KEY-----`;
const JWT_RE = String.raw`eyJ[A-Za-z0-9_\-]{5,}\.eyJ[A-Za-z0-9_\-]{5,}\.[A-Za-z0-9_\-]{8,}`;
// `&` is deliberately ALLOWED in the value class. Excluding it produced partial
// masking: `aws_secret_access_key=wJal…EXAMPLEKEY&more` masked up to the `&` and
// leaked the rest of a real secret in the clear. Over-masking a URL-ish tail costs
// nothing; under-masking a password costs the whole design.
// Backslash is likewise ALLOWED now (Req 11): a value terminated at `\` leaked the
// post-backslash tail in the clear — the same partial-mask class of failure the `&`
// regression test exists to prevent. `<` and `>` stay excluded — a value class that
// swallows angle brackets eats markup; that residual limit is documented, not
// broadened here.
// The `(?!\{\{sec:)` before the capture is load-bearing, not decoration.
// `scrubText` runs the value pass FIRST, so by the time shapes see the text a known
// secret is already `{{sec:NAME}}`. Without the lookahead, KV_RE happily captures its
// own marker (`password={{sec:gh_pat}}` -> `password={{sec:redacted}}`), which destroys
// the name the model needs to reuse the ref, and makes scrubbing non-idempotent: any
// text scrubbed twice loses every name permanently. Verified by measurement: without it
// `password=<real gh token>` degrades on the second pass; with it the name survives and
// genuine KV-shaped secrets (`api_key = wJalrXUt…`) still mask to the generic marker.
const KV_RE = String.raw`[A-Za-z0-9_\-]*(?:token|secret|password|passwd|pwd|api[_-]?key|authorization|access[_-]?key|private[_-]?key)[A-Za-z0-9_\-]*["']?\s*[=:]\s*["']?(?!\{\{sec:)([^\s"'<>]{8,})`;

/**
 * Excluded wholesale. The git-SHA rule matters most: pi prints 40-hex commit
 * hashes constantly and masking them would break normal work.
 *
 * Matched ANCHORED against the whole candidate, never as an overlap search. An
 * unanchored deny test is a false negative in the dangerous direction: the Slack
 * token `xoxb-123456789012-…` contains the 7-hex run `6789012`, and an Anthropic
 * key with a long hex tail contains a 40-hex run, so either would have been left
 * fully visible to a logging endpoint. Only a candidate that IS entirely a
 * digest-shaped token is exempt.
 */
const DENY_SOURCES = [
  "[0-9a-f]{40}", // git SHA-1
  "[0-9a-f]{64}", // sha256 digest
  "[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", // uuid
  "[0-9a-f]{7}", // short git SHA
];
const DENY_ANCHORED = new RegExp(`^(?:${DENY_SOURCES.join("|")})$`, "i");

const SHAPE_RE = new RegExp(`(?:${PEM_RE}|${JWT_RE}|${PREFIX_RE}|${KV_RE})`, "gi");

/** Whole-candidate exemption — see DENY_SOURCES for why this must not overlap-match. */
function isDenied(candidate: string): boolean {
  return DENY_ANCHORED.test(candidate);
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

export function looksCredentialish(text: string): boolean {
  const t = text.trim();
  if (t.length < 20) return false;
  if (DENY_ANCHORED.test(t)) return false; // same anchored exemption, no recompile per call
  if (/^https?:\/\//i.test(t) || /^[A-Za-z0-9._/-]+$/.test(t) && t.includes("/")) return false;
  const classes = [/[a-z]/, /[A-Z]/, /[0-9]/, /[^A-Za-z0-9\s]/].filter((r) => r.test(t)).length;
  return classes >= 2 && shannonEntropy(t) > 3.6;
}

/** Longest-first so a containing secret wins over a contained one. */
function byLengthDesc(a: string, b: string): number {
  return b.length - a.length;
}

interface Form {
  form: string;
  token: string;
}

/**
 * Whitespace map for Req 9: tool output wraps long tokens (MIME 76-col base64,
 * `kubectl -o yaml`, PEM bodies, git diffs of credential files) across
 * newlines/spaces that are NOT part of the secret. We match the form against a
 * whitespace-collapsed copy and map the hit back to the real offsets so the ENTIRE
 * wrapped span — including the inserted whitespace — is replaced, not just the
 * first line.
 *
 * This rebuilds a collapsed view per hit and never builds a `\s*`-interleaved
 * regex from the form: dozens of adjacent optional-whitespace alternations over a
 * long line is how you earn catastrophic backtracking on a path that runs on every
 * tool result.
 */
function stripWithIndex(text: string): { stripped: string; origPos: number[] } {
  const chars: string[] = [];
  const origPos: number[] = [];
  for (let i = 0; i < text.length; i++) {
    const ch = text[i]!;
    if (ch === " " || ch === "\t" || ch === "\n" || ch === "\r" || ch === "\f" || ch === "\v") continue;
    origPos[chars.length] = i;
    chars.push(ch);
  }
  return { stripped: chars.join(""), origPos };
}

/** The single matching primitive both maskValues and scrubText share, so the two
 * value passes cannot drift apart and both stay longest-first. */
function maskForms(text: string, forms: Form[]): ScrubResult {
  if (!text || forms.length === 0) return { text, hits: 0 };
  let hits = 0;
  let out = text;
  for (const { form, token } of forms) {
    if (form.length < MIN_SCRUBABLE_LENGTH) continue;
    for (;;) {
      const { stripped, origPos } = stripWithIndex(out);
      const idx = stripped.indexOf(form);
      if (idx === -1) break;
      const start = origPos[idx]!;
      // end is exclusive: one past the last matched char; the span covers any
      // wrapping whitespace between form characters, which is what we want gone.
      const end = (origPos[idx + form.length - 1] ?? start) + 1;
      out = out.slice(0, start) + token + out.slice(end);
      hits++;
    }
  }
  return { text: out, hits };
}

/** Build the candidate form set for a set of secrets, longest form first. */
function collectForms(secrets: readonly string[], tokenFor: (value: string) => string): Form[] {
  const forms: Form[] = [];
  for (const value of secrets) {
    if (value.length < MIN_SCRUBABLE_LENGTH) continue;
    const token = tokenFor(value);
    for (const form of derivedForms(value)) {
      if (form.length < MIN_SCRUBABLE_LENGTH) continue;
      forms.push({ form, token });
      // Req 10: an uppercase hex encoding of a vaulted secret is the same secret on
      // the wire (`…toString('hex').toUpperCase()`), but derivedForms yields only the
      // lowercase form. Add the uppercase twin — still a derived form, still keyed to
      // the same name — rather than entropy-scanning arbitrary hex runs, which is
      // what the brief explicitly forbids.
      if (/^[0-9a-f]+$/.test(form)) forms.push({ form: form.toUpperCase(), token });
    }
  }
  forms.sort((a, b) => byLengthDesc(a.form, b.form));
  return forms;
}

export function maskValues(text: string, secrets: readonly string[]): ScrubResult {
  return maskForms(text, collectForms(secrets, () => GENERIC));
}

export function maskShapes(text: string): ScrubResult {
  let hits = 0;
  const out = text.replace(SHAPE_RE, (match: string, ...rest: unknown[]) => {
    // When the KV alternative matched, the credential is a capture group.
    const captured = typeof rest[0] === "string" ? (rest[0] as string) : undefined;
    const target = captured ?? match;
    if (isDenied(target)) return match;
    if (target.length < MIN_SCRUBABLE_LENGTH) return match;
    hits++;
    return captured ? match.slice(0, match.length - captured.length) + GENERIC : GENERIC;
  });
  return { text: out, hits };
}

export function scrubText(text: string, vault: SecretProvider, opts: ScrubOptions = {}): ScrubResult {
  if (!text) return { text, hits: 0 };
  let out = text;
  let hits = 0;

  // Name-exact pass first: a vault value masks to its own ref so the model can reuse it.
  // Shares maskForms with maskValues (Req 9/10) so the two passes have identical
  // matching semantics — longest-first, whitespace-tolerant, hex-case-agnostic.
  const valueForms = collectForms(vault.values(), (value) => {
    const name = vault.findByValue(value)?.name;
    return name ? `{{sec:${name}}}` : GENERIC;
  });
  const r = maskForms(out, valueForms);
  if (r.hits) {
    out = r.text;
    hits += r.hits;
  }

  if (opts.shapes !== false) {
    const shapes = maskShapes(out);
    if (shapes.hits) {
      out = shapes.text;
      hits += shapes.hits;
    }
  }
  return { text: out, hits };
}

export function scrubDeep<T>(value: T, vault: SecretProvider, opts?: ScrubOptions): { value: T; hits: number } {
  let hits = 0;
  const walk = (node: unknown): unknown => {
    if (typeof node === "string") {
      const r = scrubText(node, vault, opts);
      hits += r.hits;
      return r.text;
    }
    if (Array.isArray(node)) return node.map(walk);
    if (node && typeof node === "object") {
      const out: Record<string, unknown> = {};
      for (const [k, v] of Object.entries(node)) out[k] = walk(v);
      return out;
    }
    return node;
  };
  return { value: walk(value) as T, hits };
}
