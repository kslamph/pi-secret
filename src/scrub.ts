import { MIN_SCRUBABLE_LENGTH, derivedForms, RESERVED_NAME } from "./refs.ts";
import {
  PROVIDER_PREFIXES,
  PROVIDER_PREFIX_SOURCES,
  SENSITIVE_NAME_SOURCE,
  isDigestShaped,
  isPlaceholderValue,
  hasSecretReferencePrefix,
  matchesProviderFormat,
} from "./entropy.ts";

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
  /**
   * Turns a shape match into a USABLE ref instead of the generic marker.
   *
   * Without it a credential that shows up in tool output and is not in the vault becomes
   * `{{sec:redacted}}`. The endpoint never sees it, but the model is stuck: it cannot use
   * the value, and the only way to "get it back" (od, xxd, slicing) is a leak. A session on
   * 2026-10-10 spent seven thinking blocks doing exactly that. With an adopter the value
   * goes into the session vault and the model reads `{{sec:aws_secret_access_key}}`, which
   * it can put straight into its next command. The endpoint still sees no plaintext.
   *
   * This gives the model no capability it did not already have. The value was in output
   * the model's own command produced, so bash could reach it anyway.
   *
   * Return undefined to fall back to the generic marker (cap reached, name refused).
   */
  adopt?: ShapeAdopter;
}

/** One shape match the scrubber is about to mask, with whatever names it. */
export interface ShapeHit {
  value: string;
  kind: "kv" | "provider" | "jwt" | "pem";
  /** The key on the left of a `key=value` / `key: value` match (`AWS_SECRET_ACCESS_KEY`). */
  key?: string;
  /** The provider table's hint for a provider-format match (`github`, `openai`). */
  hint?: string;
}

export type ShapeAdopter = (hit: ShapeHit) => string | undefined;

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

const GENERIC = `{{sec:${RESERVED_NAME}}}`;

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
// The two run bounds are not cosmetic and not optional: without them this pattern is
// O(n²) in the length of a single word-character run, because at every start position
// the engine consumes the whole run with the leading `*` and then backtracks one
// character at a time looking for a keyword that is not there. Measured 2026-10-10:
// `maskShapes` on 1MB of `a` did not finish in 6 seconds; with {0,32} bounds it is
// 191ms. Reachable from any tool result carrying one long unbroken word — a minified
// bundle on one line, a hex dump, a token blob — and a hang on the outbound path is a
// turn that never completes, which is exactly the failure this project refuses to cause.
// 32 is generous for a key NAME; the value class below is untouched.
const KV_RE = String.raw`[A-Za-z0-9_\-]{0,32}(?:${SENSITIVE_NAME_SOURCE})[A-Za-z0-9_\-]{0,32}["']?\s*[=:]\s*["']?(?!\{\{sec:)([^\s"'<>]{8,})`;

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

  // Fast path, and it is the whole fix: the previous version scanned the accepted
  // list per candidate, which is O(hits²). Measured 2026-10-10: 623ms at 8000 hits and
  // 32.6 SECONDS at 60000 — a 4MB log repeating a vaulted value froze the turn, in
  // tool_result, in context, and in the streaming bash display.
  //
  // A coverage bitmap instead. It is not just faster, it is linear: one form of length
  // f occurring k times in a buffer of length L satisfies k·f ≤ L, so marking every
  // span costs O(L) per form and O(forms · L) overall. The longest-first order is kept,
  // so "a containing secret wins over a contained one" is unchanged — a later, shorter
  // span is skipped because its bytes are already covered.
  spans.sort((a, b) => (b.end - b.start) - (a.end - a.start));
  const covered = new Uint8Array(text.length);
  const accepted: Span[] = [];
  for (const s of spans) {
    let clash = false;
    for (let i = s.start; i < s.end; i++) {
      if (covered[i]) {
        clash = true;
        break;
      }
    }
    if (clash) continue;
    for (let i = s.start; i < s.end; i++) covered[i] = 1;
    accepted.push(s);
  }

  // Apply in ONE pass, not one splice per span.
  //
  // This was the real quadratic term, and finding it mattered more than the dedup
  // above: the old loop rebuilt the whole string per accepted span, right-to-left, so
  // 60000 hits over a 4MB buffer copied ~240GB and took 32.6 seconds. The dedup rewrite
  // alone did not move that number at all — measured, not assumed, which is how the
  // second hotspot was found. Spans are disjoint by construction now, so a single
  // left-to-right emit with a cursor is exactly equivalent and is O(text length).
  accepted.sort((a, b) => a.start - b.start);
  const parts: string[] = [];
  let cursor = 0;
  for (const s of accepted) {
    parts.push(text.slice(cursor, s.start), s.token);
    cursor = s.end;
  }
  parts.push(text.slice(cursor));
  return { text: parts.join(""), hits: accepted.length };
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

const PROVIDER_ANCHORED = PROVIDER_PREFIXES.map((p) => ({ re: new RegExp(`^(?:${p.source})$`), hint: p.hint }));
const KV_KEY_RE = /([A-Za-z0-9_\-]+)["']?\s*[=:]\s*["']?$/;

function describeHit(match: string, captured: string | undefined): ShapeHit {
  if (captured !== undefined) {
    const key = KV_KEY_RE.exec(match.slice(0, match.length - captured.length))?.[1];
    return { value: captured, kind: "kv", key };
  }
  if (match.startsWith("-----BEGIN")) return { value: match, kind: "pem" };
  const provider = PROVIDER_ANCHORED.find((p) => p.re.test(match));
  if (provider) return { value: match, kind: "provider", hint: provider.hint };
  return { value: match, kind: "jwt" };
}

export function maskShapes(text: string, adopt?: ShapeAdopter): ScrubResult & { adopted: string[] } {
  const refSpans = existingRefSpans(text);
  const adopted: string[] = [];
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
    // The two vetoes capture.ts has applied since 2026-10-09, which the scrub path never
    // did. Measured 2026-10-10 on a vendor API page returned by get_search_content: an
    // `api_key=` line and an `apiKey:` line were both rewritten to the generic marker, so
    // the page told the model a credential had been hidden where what it actually contained
    // was an env lookup. isPlaceholderValue and hasSecretReferencePrefix give the right
    // verdict on both; they simply were never asked.
    //
    // Two scoping rules, both learned from the first version of this being too broad.
    //
    // 1. KV ALTERNATIVE ONLY, and the narrow prefix predicate rather than
    //    looksLikeSecretReference - whose DOTTED_REF_RE arm also matches a JWT, and a JWT
    //    reaching `token: eyJ...` through the KV branch would then be unmasked. The existing
    //    masks-JWTs test caught exactly that on the first attempt.
    // 2. A provider-format value is masked regardless of shape - an AWS key id enclosed in
    //    braces is placeholder-shaped and is still a credential, so the regex's prefix
    //    branch wins over either veto.
    if (captured !== undefined && !matchesProviderFormat(target)) {
      if (hasSecretReferencePrefix(target)) return match;
      if (isPlaceholderValue(target)) return match;
    }
    hits++;
    let token = GENERIC;
    if (adopt) {
      const name = adopt(describeHit(match, captured));
      if (name !== undefined) {
        token = `{{sec:${name}}}`;
        if (!adopted.includes(target)) adopted.push(target);
      }
    }
    return captured ? match.slice(0, match.length - captured.length) + token : token;
  });
  return { text: out, hits, adopted };
}

export function scrubText(text: string, vault: SecretProvider, opts: ScrubOptions = {}): ScrubResult {
  if (!text) return { text, hits: 0 };
  let out = text;
  let hits = 0;

  // Name-exact pass first: a vault value masks to its own ref so the model can reuse it.
  // Shares maskForms with maskValues (Req 9/10/12/13) so the two passes cannot drift
  // apart — one buffer, one dedup, one application loop.
  const tokenFor = (value: string): string => {
    const name = vault.findByValue(value)?.name;
    return name ? `{{sec:${name}}}` : GENERIC;
  };
  const r = maskForms(out, collectForms(vault.values(), tokenFor));
  if (r.hits) {
    out = r.text;
    hits += r.hits;
  }

  if (opts.shapes !== false) {
    const shapes = maskShapes(out, opts.adopt);
    if (shapes.hits) {
      out = shapes.text;
      hits += shapes.hits;
    }
    // A value adopted just now may ALSO appear where no shape fires: `TOKEN=abc…` on one
    // line and a bare `abc…` (or its base64) on the next. The shape pass only masked the
    // first. A second value pass over the newly vaulted values covers the rest, which the
    // generic marker never could, because it had no value to search for.
    if (shapes.adopted.length) {
      const again = maskForms(out, collectForms(shapes.adopted, tokenFor));
      out = again.text;
      hits += again.hits;
    }
  }
  return { text: out, hits };
}

/**
 * Values this walk must not treat as containers, because rebuilding them is LOSSY.
 *
 * The walk shallow-clones every container to avoid mutating the caller's graph. That is
 * safe for plain objects and arrays and catastrophic for everything else: spreading a
 * Buffer or a Uint8Array yields `{0:.., 1:..}`, and a Date yields `{}` — silent
 * corruption of data pi-secret has no business rewriting, on the same path that must
 * never produce an invalid request. Found while auditing for exactly that class of bug.
 *
 * Class instances that are NOT listed here are still walked and still cloned, because
 * their enumerable string properties are what a JSON payload carries — leaving them
 * alone would let a secret ride out inside one, which is the failure this project
 * exists to prevent.
 */
function isOpaque(n: unknown): boolean {
  return (
    ArrayBuffer.isView(n) ||
    n instanceof ArrayBuffer ||
    n instanceof Date ||
    n instanceof RegExp ||
    n instanceof Map ||
    n instanceof Set
  );
}

/**
 * Is this string leaf a BINARY PAYLOAD rather than text pi-secret may rewrite?
 *
 * Rewriting a payload is not "over-masking" — it is CORRUPTION, and the corruption is
 * what breaks the workflow. Measured 2026-10-10: reading a PNG made maskShapes match
 * the AWS access-key rule (case-insensitively, `AkIA8BxxiyzGikq3xhqm`) inside the
 * base64, so the tool result carried 4 substituted spans. The base64 no longer
 * decoded (272079 bytes instead of 272106) and the very next provider request came
 * back `400 invalid_request`. Four masked "secrets" and a dead turn.
 *
 * pi cannot redact pixels — this layer has no OCR and inventing one would be a
 * different product. So the only correct behaviour is to pass the payload through
 * byte-identical and say so out loud (the caller notifies), rather than to pretend
 * it masked one.
 *
 * Two rules, because either alone is incomplete:
 *  - STRUCTURAL: a `data` field whose block declares a non-text `mimeType`, or a
 *    `type` of image/audio. That is exactly the shape pi's read tool emits
 *    (`{type:"image", data, mimeType, note}`), and the `note` beside it is still
 *    prose, so it keeps being scrubbed.
 *  - CONTENT: an unbroken base64 run long enough that no prose can be. The bound is
 *    2048 characters because the shortest thing this must catch in practice is a
 *    small screenshot's payload, and the longest thing that must NOT be exempted is
 *    an ordinary token — a 20-character AWS key is masked, as the test pins.
 */
const BINARY_PAYLOAD_MIN = 2048;
const BASE64_RUN = /^[A-Za-z0-9+/_-]+={0,2}$/;

function isBinaryPayload(parent: Record<string, unknown> | unknown[], key: string, value: string): boolean {
  if (key === "data" && !Array.isArray(parent)) {
    const mime = parent.mimeType;
    if (typeof mime === "string" && mime !== "" && !/^text\//i.test(mime)) return true;
    const type = parent.type;
    if (typeof type === "string" && /^(?:image|audio|video)$/i.test(type)) return true;
  }
  if (value.length < BINARY_PAYLOAD_MIN) return false;
  if (value.length % 4 === 1) return false;
  return BASE64_RUN.test(value);
}

/**
 * One iterative deep-walk shared by scrubDeep and redactAllText.
 *
 * EXPLICIT STACK, NOT RECURSION, and that is load-bearing rather than stylistic. The
 * recursive version died at ~5000 levels with `RangeError: Maximum call stack size
 * exceeded` (measured, not theoretical — a model can emit a tool-call argument nested
 * that deep). A throw inside a pi extension handler is NOT a crash: every one of
 * `emitContext` and `emitBeforeProviderRequest` wraps each handler in try/catch,
 * calls `emitError`, and returns the value it held BEFORE the failing handler ran. So
 * the stack overflow was scrubbing being silently skipped on exactly the surface this
 * design forbids from failing open — the bytes handed to the provider. An
 * unbounded-depth walk turns that class of bug from "impossible" into "reachable".
 *
 * Shallow-copies each container so the caller's object graph is never mutated, and
 * preserves non-string leaves and key order exactly as the recursive version did.
 */
function walkDeep<T>(
  value: T,
  onString: (s: string) => string,
  onHit?: () => void,
  preserveKeys?: ReadonlySet<string>,
  onSkipBinary?: () => void,
): T {
  const isContainer = (n: unknown): n is Record<string, unknown> | unknown[] =>
    !isOpaque(n) && (Array.isArray(n) || (n !== null && typeof n === "object"));
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
      // A payload is not text. Rewriting one corrupts it (see isBinaryPayload), so it
      // is skipped entirely — both passes, fail-closed included — and counted, because
      // silence here would read as "pi-secret checked and found nothing".
      if (isBinaryPayload(frame.src, key, child)) {
        onSkipBinary?.();
        continue;
      }
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

export function scrubDeep<T>(
  value: T,
  vault: SecretProvider,
  opts?: ScrubOptions,
): { value: T; hits: number; skippedBinary: number } {
  let hits = 0;
  let skippedBinary = 0;
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
    () => {
      skippedBinary++;
    },
  );
  return { value: scrubbed, hits, skippedBinary };
}

/**
 * The keys a redaction must NOT touch, because the provider validates them.
 *
 * Fail-closed used to replace every string in the payload. That is correct for prose and
 * fatal for structure: `role: "user"` becomes `role: "{{sec:redacted}}"` and the request
 * is rejected — so the one time the fallback fires it converts a redaction into a 400,
 * which is precisely the workflow break this project refuses to cause. These fields are
 * enums and identifiers, never prose, so nothing is lost by leaving them alone.
 */
const STRUCTURAL_KEYS: ReadonlySet<string> = new Set([
  "role",
  "type",
  "mimeType",
  "name",
  "id",
  "toolCallId",
  "tool_call_id",
  "index",
  "status",
  "model",
  "api",
  "provider",
  "stopReason",
  "finish_reason",
]);

/**
 * Redact one string, keeping any JSON inside it parseable.
 *
 * A tool call's `arguments` can travel as a JSON *string*, and a bare marker in that
 * position is not valid JSON — another 400 from the last-resort path. Parsing and
 * re-serialising with the leaves redacted keeps the field usable and loses no
 * protection: the secret was inside a string leaf either way.
 */
function redactStringKeepingJson(s: string): string {
  const t = s.trimStart();
  if (t.startsWith("{") || t.startsWith("[")) {
    try {
      return JSON.stringify(walkDeep(JSON.parse(s) as unknown, () => GENERIC));
    } catch {
      // Not JSON after all; fall through to the plain marker.
    }
  }
  return GENERIC;
}

/**
 * The fail-closed fallback (spec §11): replace every string leaf with the redaction
 * marker, using the same unbounded-depth walk so it cannot itself throw. Used when
 * scrubDeep raises — over-redacting costs the model some context, under-redacting
 * costs the user the credential, so the bias is deliberate and one-directional.
 *
 * Bounded by the two rules above: binary payloads pass through (rewriting them would
 * corrupt the image) and the provider's structural fields are preserved (rewriting them
 * would reject the request). Prose — the only place a secret can actually hide — is
 * still redacted wholesale.
 */
export function redactAllText<T>(value: T): T {
  return walkDeep(value, redactStringKeepingJson, undefined, STRUCTURAL_KEYS);
}
