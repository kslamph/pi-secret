import { MIN_SCRUBABLE_LENGTH, derivedForms } from "./refs.ts";
import { PROVIDER_PREFIX_SOURCES, SENSITIVE_NAME_SOURCE, isDigestShaped } from "./entropy.ts";

export interface SecretProvider {
  values(): string[];
  findByValue(value: string): { name: string } | undefined;
}

export interface ScrubOptions {
  /** Shape masking. Default true. Disable for file-content reads to avoid corrupting write-back. */
  shapes?: boolean;
  /**
   * Keys whose string values are left EXACTLY as they are, however credential-shaped
   * they look.
   *
   * Exists for `details.fullOutputPath`, which is a filesystem pointer rather than
   * model-facing text. Scrubbing it is not merely useless: if the path matches a
   * shape, the pointer handed to `scrubOutputSnapshot` no longer exists, the rewrite
   * fails, and the fail-closed branch deletes the pointer — correct for the model, but
   * it leaves the UNSCRUBBED snapshot on disk with nothing pointing at it. A masked
   * pointer converts a leak into an invisible one.
   */
  preserveKeys?: ReadonlySet<string>;
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
const PREFIX_RE = `(?:${PROVIDER_PREFIX_SOURCES.join("|")})`;

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
// The word list is shared with `entropy.ts` (§12g's classifier is its third consumer): a name that
// says "token" or "api_key" is a secret-shaped name in every context this project has, and two
// copies of that judgement is the drift the design keeps paying for.
const KV_RE = String.raw`[A-Za-z0-9_\-]*(?:${SENSITIVE_NAME_SOURCE})[A-Za-z0-9_\-]*["']?\s*[=:]\s*["']?(?!\{\{sec:)([^\s"'<>]{8,})`;

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

import { REF_RE } from "./refs.ts";

/**
 * Spans of refs ALREADY present in the text, so the shape pass can leave their
 * interiors alone.
 *
 * This exists because `scrubText` runs the value pass first: by the time shapes see
 * the buffer, the value has already become `{{sec:NAME}}`. The KV alternative had a
 * `(?!\{\{sec:)` lookahead, but PREFIX_RE / JWT_RE / PEM_RE had no equivalent — so a
 * secret whose NAME is itself credential-shaped (reachable by typing
 * `/sec add sk-aaaa…`; isValidName allows it) was destroyed by our own scrubber in
 * the same pass that created it, becoming `{{sec:{{sec:redacted}}}}`. Stable and
 * idempotent, and useless: the name the model needs in order to reuse the secret is
 * gone, which breaks the design's round-trip property for that entry.
 *
 * A span check rather than another lookahead per alternative, because the prefix
 * family is a dozen branches and a guard written inside one of them is a guard that
 * silently stops applying to the other eleven.
 */
function existingRefSpans(text: string): Array<[number, number]> {
  const spans: Array<[number, number]> = [];
  REF_RE.lastIndex = 0;
  for (let m = REF_RE.exec(text); m !== null; m = REF_RE.exec(text)) {
    spans.push([m.index, m.index + m[0].length]);
  }
  return spans;
}

export function maskShapes(text: string): ScrubResult {
  const refSpans = existingRefSpans(text);
  let hits = 0;
  const out = text.replace(SHAPE_RE, (match: string, ...rest: unknown[]) => {
    // `rest` is [capture?, offset, string]; the offset is what decides whether this
    // match lands inside a ref we must not touch.
    const offset = rest[rest.length - 2];
    if (typeof offset === "number" && refSpans.some(([s, e]) => offset < e && offset + match.length > s)) {
      return match;
    }
    // When the KV alternative matched, the credential is a capture group.
    const captured = typeof rest[0] === "string" ? (rest[0] as string) : undefined;
    const target = captured ?? match;
    if (isDigestShaped(target)) return match;
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

/**
 * One iterative deep-walk shared by scrubDeep and redactAllText.
 *
 * EXPLICIT STACK, NOT RECURSION, and that is load-bearing rather than stylistic. The
 * recursive version died at ~5000 levels with `RangeError: Maximum call stack size
 * exceeded` (measured, not theoretical — a model can emit a tool-call argument nested
 * that deep). A throw inside a pi extension handler is NOT a crash: every one of
 * `emitMessageEnd`, `emitContext` and `emitBeforeProviderRequest` wraps each handler
 * in try/catch, calls `emitError`, and returns the value it held BEFORE the failing
 * handler ran. So the stack overflow was scrubbing being silently skipped on exactly
 * the two surfaces this design forbids from failing open — the persisted assistant
 * message and the bytes handed to the provider. An unbounded-depth walk turns that
 * class of bug from "impossible" into "reachable".
 *
 * Shallow-copies each container so the caller's object graph is never mutated, and
 * preserves non-string leaves and key order exactly as the recursive version did.
 */
function walkDeep<T>(
  value: T,
  onString: (s: string) => string,
  onHit?: () => void,
  preserveKeys?: ReadonlySet<string>,
): T {
  const isContainer = (n: unknown): n is Record<string, unknown> | unknown[] =>
    Array.isArray(n) || (n !== null && typeof n === "object");
  const clone = (n: Record<string, unknown> | unknown[]): Record<string, unknown> | unknown[] =>
    Array.isArray(n) ? n.slice() : { ...n };
  const keysOf = (n: Record<string, unknown> | unknown[]): string[] =>
    Array.isArray(n) ? n.map((_, i) => String(i)) : Object.keys(n);

  if (!isContainer(value)) {
    if (typeof value === "string") return onString(value) as T;
    return value;
  }

  const out = clone(value);
  const stack: { src: Record<string, unknown> | unknown[]; dst: Record<string, unknown> | unknown[]; keys: string[]; i: number }[] = [
    { src: value, dst: out, keys: keysOf(value), i: 0 },
  ];
  while (stack.length) {
    const frame = stack[stack.length - 1]!;
    if (frame.i >= frame.keys.length) {
      stack.pop();
      continue;
    }
    const key = frame.keys[frame.i++]!;
    if (preserveKeys?.has(key)) continue;
    const child = (frame.src as Record<string, unknown>)[key];
    if (typeof child === "string") {
      (frame.dst as Record<string, unknown>)[key] = onString(child);
    } else if (isContainer(child)) {
      const copy = clone(child);
      (frame.dst as Record<string, unknown>)[key] = copy;
      stack.push({ src: child, dst: copy, keys: keysOf(child), i: 0 });
    }
    // Non-string, non-container leaves were already carried over by the shallow
    // clone; nothing to visit.
  }
  onHit?.();
  return out as T;
}

export function scrubDeep<T>(value: T, vault: SecretProvider, opts?: ScrubOptions): { value: T; hits: number } {
  let hits = 0;
  const scrubbed = walkDeep(
    value,
    (s) => {
      const r = scrubText(s, vault, opts);
      hits += r.hits;
      return r.text;
    },
    () => {
      /* hits accumulates in the closure above */
    },
    opts?.preserveKeys,
  );
  return { value: scrubbed, hits };
}

/**
 * The fail-closed fallback (spec §11): replace EVERY string leaf with the redaction
 * marker, using the same unbounded-depth walk so it cannot itself throw. Used when
 * scrubDeep raises — over-redacting costs the model some context, under-redacting
 * costs the user the credential, so the bias is deliberate and one-directional.
 */
export function redactAllText<T>(value: T): T {
  return walkDeep(value, () => GENERIC);
}
