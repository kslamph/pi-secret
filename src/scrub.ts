import { MIN_SCRUBABLE_LENGTH, derivedForms } from "./refs.ts";

export interface SecretProvider {
  values(): string[];
  findByValue(value: string): { name: string } | undefined;
}

export interface ScrubOptions {
  /** Shape masking. Default true. Disable for file-content reads to avoid corrupting write-back. */
  shapes?: boolean;
}

/** Result of a scrub pass over a string. */
export interface ScrubResult {
  text: string;
  /**
   * Number of masked *regions* replaced, NOT the count of distinct secrets redacted.
   * Two encodings of the same vault secret at separate offsets count as 2; a raw
   * value plus one of its encodings landing on the same span count as 1 (the batch
   * dedup keeps only the longest winning span). Task 8 receipts must not read this
   * field as "N secrets redacted" — it is `maskedSpanCount`.
   */
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

/**
 * Single source of truth for the whitespace set (Req 17). `stripWhitespace` and
 * `buildOrigPos` both derive from `WS`, so a future "cleanup" to `/\s+/` on one side
 * cannot silently shift offsets and mask the wrong span — the dangerous failure mode
 * is a whitespace set that swallows more/less than the index map expects. This is the
 * exact set `[ \t\n\r\f\v]`; NBSP and U+2028 are deliberately NOT whitespace here.
 */
const WS = /[ \t\n\r\f\v]/;
const WHITESPACE_RE = new RegExp(WS.source, "g");

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

/**
 * A form + the token that replaces it. `kind` is inferred from the form's VALUE
 * (Req 15), never its position in the `derivedForms` array, so a future reorder or
 * pre-filter of `derivedForms` cannot flip a raw value to an encoding (or vice versa)
 * and silently reintroduce the Req 12 prose-mangling bug.
 */
interface Form {
  form: string;
  token: string;
  kind: "raw" | "encoding";
  /** A head/tail window of a longer encoding (Task 16). A match means "this
   *  secret's encoding is present but CUT"; the span is then grown over
   *  `alphabet` so the whole visible run is masked, not just the window. */
  window?: boolean;
  alphabet?: RegExp;
}

/**
 * Task 16 — truncation-aware masking.
 *
 * An encoding is only masked today when the WHOLE form appears. pi's bash tool
 * truncates to the last 5000 lines / 50KB and can return a PARTIAL last line, so
 * the surviving fragment is usually the TAIL: measured, an 88-char encoding cut at
 * 84 leaves 94% of it visible and nothing masked.
 *
 * Two guards keep windowing from becoming a prose-eater. `WINDOW_MIN_FORM` stops
 * short encodings being windowed at all — an 8-byte secret's base64 is 12 chars and
 * its prefix is plausible inside ordinary text, so that case stays on the
 * whole-form match. And the extension below can only GROW a match that an exact
 * 24-char window already proved, so it never turns prose into a match.
 */
const WINDOW_MIN_FORM = 40;
/** Length of each window: two per encoding (head and tail), not one per cut point. */
const WINDOW_SIZE = 24;

/**
 * Characters that can belong to an encoding — the bound on run extension.
 * Checked hex-first: hex's alphabet is a subset of base64's, so the order is what
 * keeps a hex run from extending across adjacent base64-looking text.
 */
function alphabetFor(form: string): RegExp {
  if (/^[0-9a-f]+$/i.test(form)) return /[0-9a-fA-F]/;
  if (form.includes("-") || form.includes("_")) return /[A-Za-z0-9_-]/;
  return /[A-Za-z0-9+/=]/;
}

interface Span {
  start: number;
  end: number;
  token: string;
}

/**
 * Whitespace-stripped copy of `text` (the shared scan buffer, Req 13). When the text
 * contains no whitespace, returns the text itself so callers can skip offset mapping.
 */
function stripWhitespace(text: string): string {
  if (!WS.test(text)) return text;
  WHITESPACE_RE.lastIndex = 0;
  return text.replace(WHITESPACE_RE, "");
}

/**
 * Original offset of the i-th non-whitespace character. Built LAZILY (Req 13) only
 * when an encoding form actually matches — the common case (secrets absent from a tool
 * result) never pays this cost. Shares the `WS` class with stripWhitespace (Req 17).
 */
function buildOrigPos(text: string): number[] {
  const len = text.length;
  const out: number[] = [];
  for (let i = 0; i < len; i++) {
    const ch = text[i]!;
    if (WS.test(ch)) continue;
    out[out.length] = i;
  }
  return out;
}

/** The single matching primitive both maskValues and scrubText share. */
function maskForms(text: string, forms: Form[]): ScrubResult {
  if (!text || forms.length === 0) return { text, hits: 0 };

  // Req 13: one stripped buffer for the whole text, reused by every encoding form.
  const stripped = stripWhitespace(text);
  const noWhitespace = stripped === text;
  let origPos: number[] | null = null;

  // Collect every occurrence, all in ORIGINAL offset space so raw (text coords) and
  // encoding (stripped coords mapped back) spans coexist.
  const spans: Span[] = [];
  for (const { form, token, kind, window, alphabet } of forms) {
    if (form.length < MIN_SCRUBABLE_LENGTH) continue;
    const search = kind === "raw" ? text : stripped;
    let idx = search.indexOf(form);
    if (idx === -1) continue;
    if (kind === "encoding" && !noWhitespace && origPos === null) origPos = buildOrigPos(text);
    for (;;) {
      // A window match proves the encoding is present but cut. Mask the whole
      // visible run rather than the window alone, so any cut point is covered:
      // extend outward over the encoding's own alphabet. Operating on `search`
      // (the whitespace-stripped buffer for encodings) is what makes this
      // whitespace-tolerant, which matters because tools wrap and truncate.
      let s = idx;
      let e = idx + form.length;
      if (window && alphabet && kind === "encoding") {
        // Extend over the encoding's own alphabet, but NEVER across whitespace.
        // The stripped buffer makes whitespace invisible, so two characters can be
        // adjacent here and far apart in the original; consult the original offsets
        // and stop at a gap. Without this, `<encoding> and then some prose` masks the
        // prose as well, because "and" is entirely base64-alphabet. Over-masking is
        // the worse failure: it makes ordinary output unreadable, and unreadable
        // output is how users start pasting tokens by hand (plan's stop rule).
        const contiguous = (k: number): boolean => noWhitespace || origPos![k] === origPos![k - 1]! + 1;
        while (e < search.length && alphabet.test(search[e]!) && contiguous(e)) e++;
        while (s > 0 && alphabet.test(search[s - 1]!) && contiguous(s)) s--;
      }
      if (kind === "raw" || noWhitespace) {
        // contiguous: stripped===text so stripped-index == text-index
        spans.push({ start: s, end: e, token });
      } else {
        const start = origPos![s]!;
        const end = (origPos![e - 1] ?? start) + 1;
        spans.push({ start, end, token });
      }
      idx = search.indexOf(form, idx + form.length);
      if (idx === -1) break;
    }
  }

  // Longest span wins on overlap — preserves the old per-form "longest first"
  // semantics (a containing secret must mask before a contained one).
  spans.sort((a, b) => (b.end - b.start) - (a.end - a.start));
  const accepted: Span[] = [];
  for (const s of spans) {
    let overlap = false;
    for (const a of accepted) {
      if (s.start < a.end && s.end > a.start) {
        overlap = true;
        break;
      }
    }
    if (!overlap) accepted.push(s);
  }

  // Apply right-to-left so earlier spans' offsets stay valid as later ones shrink.
  accepted.sort((a, b) => b.start - a.start);
  let out = text;
  for (const s of accepted) {
    out = out.slice(0, s.start) + s.token + out.slice(s.end);
  }
  return { text: out, hits: accepted.length };
}

/** Build the candidate form set for a set of secrets, longest form first. */
function collectForms(secrets: readonly string[], tokenFor: (value: string) => string): Form[] {
  const forms: Form[] = [];

  /**
   * Register one encoding plus, when it is long enough to be safe, a head and a
   * tail window (Task 16). Every encoding goes through here — including the
   * unpadded and uppercase-hex variants derived below — because a truncated
   * `base64 -w0 | tr -d '='` or a truncated uppercase-hex encoding is exactly as
   * exposed as a truncated padded one, and windowing only the first form of each
   * kind would have left those two silently unmasked.
   */
  const addEncoding = (form: string, token: string): void => {
    forms.push({ form, token, kind: "encoding" });
    if (form.length < WINDOW_MIN_FORM) return;
    const alphabet = alphabetFor(form);
    forms.push({ form: form.slice(0, WINDOW_SIZE), token, kind: "encoding", window: true, alphabet });
    forms.push({ form: form.slice(-WINDOW_SIZE), token, kind: "encoding", window: true, alphabet });
  };

  for (const value of secrets) {
    if (value.length < MIN_SCRUBABLE_LENGTH) continue;
    const token = tokenFor(value);
    // `form === value` identifies the raw value form by VALUE, not array index (Req 15).
    for (const form of derivedForms(value)) {
      if (form.length < MIN_SCRUBABLE_LENGTH) continue;
      const kind: "raw" | "encoding" = form === value ? "raw" : "encoding";
      if (kind === "raw") {
        // NEVER window a raw value: that is the prose-mangling class spec §12.10
        // records, and an 8-character vault entry makes it reachable.
        forms.push({ form, token, kind });
        continue;
      }
      addEncoding(form, token);
      // Req 14: standard base64 with padding stripped (`base64 -w0 | tr -d '='`).
        // Among encodings only padded standard base64 ends with `=`, so this is
        // index-free and survives a derivedForms reorder.
        if (form.endsWith("=")) {
          const unpadded = form.replace(/=+$/, "");
          // Req 16: re-state the MIN invariant here (unreachable today: an 8-byte
          // value yields >= 11 unpadded base64 chars), so a future encoding whose
          // padding strip could undercut the floor is caught at the push.
          if (unpadded.length >= MIN_SCRUBABLE_LENGTH) {
            addEncoding(unpadded, token);
          }
        }
        // Req 10: uppercase hex twin (hex encoding only) — still a derived form
        // keyed to the same name, never an entropy scan of arbitrary hex runs.
        if (/^[0-9a-f]+$/.test(form)) {
          addEncoding(form.toUpperCase(), token);
        }
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
  // Shares maskForms with maskValues (Req 9/10/12/13) so the two passes cannot drift
  // apart — one buffer, one dedup, one application loop.
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
