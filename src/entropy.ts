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

/**
 * Anchored provider formats, most specific prefix first so `dckr_pat_` wins over
 * `pat_`-like forms and `sk-ant-` wins over `sk-`.
 *
 * This table lives here, not in scrub.ts, because it answers a question BOTH sides need:
 * the scrubber uses it to decide what to mask, and the preview uses it to decide what may
 * be shown. Two copies of "what does a credential look like" is exactly the drift this
 * project keeps paying for.
 *
 * Built as an array of single-line sources joined with `|`, and NOT as a multi-line
 * String.raw template: a template literal there embeds real newlines and indentation into
 * the pattern, so `(?:\n  dckr_pat_…` would demand a newline before every token and match
 * nothing — a silent, total failure of shape scrubbing. There is no `x` (verbose) flag in
 * this V8 to make the readable form work: `new RegExp(src, "gx")` throws SyntaxError at
 * module load.
 */
export const PROVIDER_PREFIXES: ReadonlyArray<{ hint: string; source: string }> = [
  { hint: "docker_pat", source: "dckr_pat_[A-Za-z0-9_\\-]{20,}" },
  { hint: "github_pat", source: "github_pat_[A-Za-z0-9_]{20,}" },
  { hint: "github", source: "gh[pousr]_[A-Za-z0-9]{20,}" },
  { hint: "anthropic", source: "sk-ant-[A-Za-z0-9_\\-]{20,}" },
  // `sk-` with no marker is OpenAI. It was MISSING from capture.ts's copy of this table,
  // so `sk-proj-…` was recognised by the scrubber and the preview but only ever captured
  // as an entropy-tier guess. Tier 1 is where a provider format belongs: it carries the
  // hint, it cannot mis-slice, and it survives any tightening of tier 3.
  { hint: "openai", source: "sk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_\\-]{20,}" },
  { hint: "google", source: "AIza[0-9A-Za-z_\\-]{30,}" },
  // The other AWS identifier prefixes, not just the two access-key ones: a role id or an
  // account id pasted into a prompt is as much a credential as AKIA.
  { hint: "aws_access_key_id", source: "(?:AKIA|ASIA|AGPA|AIDA|AROA|ANPA|ANVA|AIPA)[0-9A-Z]{16}" },
  { hint: "slack", source: "xox[baprs]-[A-Za-z0-9\\-]{10,}" },
  { hint: "gitlab", source: "glpat-[A-Za-z0-9_\\-]{20,}" },
  { hint: "npm", source: "npm_[A-Za-z0-9]{30,}" },
  { hint: "pypi", source: "pypi-Po-[A-Za-z0-9]{20,}" },
  { hint: "huggingface", source: "hf_[A-Za-z0-9]{20,}" },
  { hint: "stripe", source: "[sr]k_(?:live|test)_[0-9A-Za-z]{16,}" },
  { hint: "sendgrid", source: "SG\\.[A-Za-z0-9_\\-]{16,}\\.[A-Za-z0-9_\\-]{16,}" },
];

export const PROVIDER_PREFIX_SOURCES = PROVIDER_PREFIXES.map((p) => p.source);

/** The whole value matches a known provider key format. Anchored, never a substring test. */
const PROVIDER_FORMAT_ANCHORED = new RegExp(`^(?:${PROVIDER_PREFIX_SOURCES.join("|")})$`);
export function matchesProviderFormat(value: string): boolean {
  return PROVIDER_FORMAT_ANCHORED.test(value);
}

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
/** Whitespace, quoting, or shell metacharacters: the difference between code and a token. */
const SHELL_SYNTAX = /[\s\\`{}()<>|;&*?!'"]/;
/** `~`, `/`, `./`, `../`, or a Windows drive root. */
const PATH_STEM = /^(?:~|[A-Za-z]:[\\/]|\/|\.\.?\/)/;
const URL_SCHEME = /^[a-z][a-z0-9+.-]*:\/\//i;
const URL_WITH_USERINFO = /^[a-z][a-z0-9+.-]*:\/\/([^/?#@]*@)/i;

export function looksCredentialish(text: string): boolean {
  const t = text.trim();
  if (t.length < 20) return false;
  if (isDigestShaped(t)) return false; // same anchored exemption, no recompile per call
  // A scheme URL that carries userinfo is a secret in a URL (`postgres://user:pass@host/db`), and
  // must be accepted BEFORE the plain-URL rejection below. Host-based rules (capture's
  // `isCredentialUrl` and its CRED_HOST_PATHS table) stay in capture: this predicate answers only
  // what the STRING looks like, and userinfo is the part of that which is visible in the string.
  if (URL_WITH_USERINFO.test(t)) return true;
  if (URL_SCHEME.test(t)) return false;
  // Shell structure. This is the 2026-10-08 correction: a real `~/.bashrc` had six of its eight
  // "likely secret" rows be shell code, because entropy cannot tell a prompt string from a token.
  // `PS1='${debian_chroot:+($debian_chroot)}\u@\h:\w\$ '` is high-entropy, multi-class, and not
  // a secret; a credential is a single opaque token and never contains whitespace or shell syntax.
  if (SHELL_SYNTAX.test(t)) return false;
  if (PATH_STEM.test(t)) return false;
  if (t.startsWith("-")) return false; // CLI flags and `--a,--b` argument lists
  // A colon- or comma-separated list is a PATH or an argument list, not one token. The `://`
  // exemption keeps DSNs (already accepted above) and scheme URLs out of this rule's way.
  if (!t.includes("://") && /[:,]/.test(t)) return false;
  if (/^[A-Za-z0-9._/-]+$/.test(t) && t.includes("/")) return false; // filesystem path
  const classes = [/[a-z]/, /[A-Z]/, /[0-9]/, /[^A-Za-z0-9\s]/].filter((r) => r.test(t)).length;
  return classes >= 2 && shannonEntropy(t) > 3.6;
}

/**
 * Is this text built out of WORDS rather than random bytes?
 *
 * The entropy tier's real discriminator, and the one its own author reached for too
 * late. Shannon entropy cannot tell `NewPaymentCaseReconcilerFromContext` from a secret,
 * because both mix cases and neither repeats much: measured 4.14 vs 3.99 bits/char
 * respectively — the identifier scores HIGHER. What separates them is structure: a name
 * is built from word runs (`[A-Z]?[a-z]{3,}` — "New", "Payment", "Case", …), while random
 * bytes produce one- and two-letter runs almost exclusively. So the ratio of characters
 * inside word runs is the signal entropy was supposed to be.
 *
 * TWO runs are required, not one. Measured: a 26-character secret of sixteen lowercase
 * letters followed by ten digits has a single run covering 62% of it, so a ratio-only rule
 * classified that credential as an identifier and dropped it. Random text stretches its
 * letters out; only a NAME chains several of them together.
 */
const WORD_RUN_RE = /[A-Z]?[a-z]{3,}/g;
export const IDENTIFIER_WORD_RATIO = 0.6;

export function looksLikeIdentifierText(value: string): boolean {
  const runs = value.match(WORD_RUN_RE);
  if (!runs || runs.length < 2) return false;
  const wordChars = runs.reduce((n, w) => n + w.length, 0);
  return wordChars / value.length >= IDENTIFIER_WORD_RATIO;
}

/**
 * Placeholder values: templates, doc examples, redaction markers, type names.
 *
 * Anchored to the WHOLE value, never a substring test, because the whole point is that
 * `password=secret` is not a secret while a twelve-character password is. Without this,
 * every `token: <your-token-here>` and every `change-me` in a pasted config was rewritten
 * into a ref, which is worse than missing: the user loses the literal they were reading.
 */
const PLACEHOLDER_VALUE_RE = new RegExp(
  "^(?:" +
    [
      "x{3,}",
      "\\*{3,}",
      "\\.{3,}",
      "-{3,}",
      "_{3,}",
      "<[^>]*>",
      "\\[[^\\]]*\\]",
      "\\{\\{[^}]*\\}\\}",
      "\\$\\{[^}]*\\}",
      "%[A-Za-z_]+%",
      "your[-_ ]?\\w*",
      "change[-_]?me",
      "replace[-_]?me",
      "placeholder",
      "redacted",
      "dummy",
      "sample",
      "example",
      "todo",
      "null|none|nil|undefined|true|false|empty",
      "string|str|int|integer|number|bool|boolean|any|object|required|optional",
      "env|secret|password|passwd|pwd|token|api[-_]?key|credential|auth",
      "test|tests|foobar|xxx+",
    ].join("|") +
    ")$",
  "i",
);

export function isPlaceholderValue(value: string): boolean {
  const v = value.trim();
  return v.length === 0 || PLACEHOLDER_VALUE_RE.test(v);
}

/**
 * A REFERENCE to a secret, not the secret: an env lookup, a call, a typed slot.
 *
 * This is the rule that stopped capture from rewriting working code into broken code.
 * Before it, a line calling a password helper was captured as a secret, and an env lookup
 * was captured as its own TRUNCATED PREFIX — the text up to the opening quote, out of the
 * whole call — which is a rewrite that changes what the code means. capture.ts's own
 * comment already called over-capture the accepted failure direction; this is the case
 * where accepting it was simply wrong.
 *
 * Deliberately narrow: a bare word is NOT a reference (`hunter2` is a password), so the
 * dotted and called forms require their punctuation. A JWT has dots too, but tier 1
 * catches it before any value-level filter runs, and no anchored candidate is vetoed here.
 */
const REFERENCE_PREFIX_RE =
  /^(?:\$|%[A-Za-z_]+|@|process\.env|os\.environ|os\.getenv|System\.getenv|ENV\[|env\.|config\.|settings\.|self\.|this\.|args\.|opts\.|options\.|req\.|request\.|params\.|input\(|getpass|prompt\()/i;
const DOTTED_REF_RE = /^[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)+\(?\)?$/;
const CALLED_REF_RE = /^[A-Za-z_]\w*\(\)?$/;
/**
 * A typed slot, e.g. `Optional[str]`.
 *
 * A PREFIX test, not an anchored one, and that detail is load-bearing: the value that
 * reaches this predicate has already been delimiter-trimmed, and trimming strips a
 * trailing bracket — so an anchored `^[A-Z]\w*\[.*\]$` misses exactly the case it exists
 * for, and a Rust line that declares a `password` field of an optional string gets
 * captured as a secret whose value is the type name minus its last character. A secret
 * never begins with a bracketed type name; base64 has no brackets at all.
 */
const TYPED_SLOT_RE = /^[A-Z]\w*\[/;

export function looksLikeSecretReference(value: string): boolean {
  const v = value.trim();
  return (
    REFERENCE_PREFIX_RE.test(v) ||
    DOTTED_REF_RE.test(v) ||
    CALLED_REF_RE.test(v) ||
    TYPED_SLOT_RE.test(v)
  );
}

/**
 * The words that mark a NAME as credential-bearing, kept in one place on purpose.
 *
 * `scrub.ts` builds its key/value pattern from this same source. Two copies of "what does a
 * credential look like" is the drift this project keeps paying for, and the third consumer
 * (the file-import classifier) is what made sharing it worth doing now.
 */
export const SENSITIVE_NAME_SOURCE =
  "(?:token|secret|password|passwd|pwd|api[_-]?key|authorization|access[_-]?key|private[_-]?key)";

const SENSITIVE_NAME_RE = new RegExp(`^[a-z0-9_\\-]*${SENSITIVE_NAME_SOURCE}[a-z0-9_\\-]*$`, "i");

/**
 * Names that say "this is an identifier or a setting", so a random-looking value is still not a key.
 *
 * Needed because shape genuinely cannot decide: `CLOUDFLARE_ACCOUNT_ID=7f3a9c…` is 32 random-looking
 * hex characters, and no entropy rule separates that from a 32-character hex token. The name is the
 * only evidence available, so it has to be allowed to veto. Without this, whether that row shows up
 * depends on how much repetition the particular account ID happens to contain — a real row from a
 * real `.bashrc`, flagged or not by luck.
 *
 * `url` and `key` are deliberately absent: a DSN carries a password, and a signed URL is itself a
 * credential, so those keep their chance to be shown. `pwd` IS here, because in a shell file `PWD`
 * is a directory while `pwd` in the scrubber's word list means a password — the same word, two
 * meanings, and the file-import reading is the literal one.
 */
const IDENTIFIER_NAME_RE = new RegExp(
  "^(?:" +
    [
      "port|host|hostname|user|username|shell|term|editor|visual|path|home|pwd",
      "lang|locale|tz|color|colour|theme|version|region|zone|mode|level",
      "[a-z0-9_]+_(?:id|ids|name|path|paths|home|dir|dirs|list|count|total|version|region|zone|host|hostname|port|size|locale|lang|tz|time|date|mode|level)",
    ].join("|") +
    ")$",
  "i",
);

export function looksLikeIdentifierName(name: string): boolean {
  return IDENTIFIER_NAME_RE.test(name.trim());
}

/** `CLINE_API_KEY`, `gh_token`, `my-app_secret`. Bare `key` is deliberately absent: `monkey`. */
export function looksLikeSensitiveName(name: string): boolean {
  return SENSITIVE_NAME_RE.test(name.trim());
}

/**
 * The file-import classifier (spec §12g): should this assignment be OFFERED as a secret?
 *
 * Three signals, because each one alone fails on a real file — measured against a shell profile,
 * not guessed:
 *
 *  - the provider prefix (`ghp_…`) — near-zero false positives, and it catches a token exported
 *    under a name that says nothing (`GH_PAT`);
 *  - the name (`*_API_KEY`, `*_TOKEN`) — the only signal that catches a real key whose value is
 *    short or oddly shaped, which is exactly the case a shape-only rule loses;
 *  - the value's shape — an opaque single token, which catches a secret under a neutral name
 *    (`LEGACY_KEY`).
 *
 * Being wrong here is cheap in only one direction: the list shows everything on request, so a
 * missed secret costs a keypress, while a false positive costs the user's attention on every
 * import. That asymmetry is why the shape rule is strict.
 */
export function isLikelySecret(name: string, value: string): boolean {
  // Order is the design. An unambiguous provider prefix is a secret whatever it is called, which
  // rescues `GH_PAT=ghp_…`. A name that says "identifier or setting" is believed over an ambiguous
  // value shape. Only then does the sensitive-name signal apply, and last of all the shape — so a
  // secret under a neutral name (`LEGACY_KEY`) is still found.
  if (matchesProviderFormat(value.trim())) return true;
  if (looksLikeIdentifierName(name)) return false;
  if (looksLikeSensitiveName(name)) return true;
  return looksCredentialish(value);
}