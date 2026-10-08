import { closeSync, openSync, readSync, readdirSync, statSync } from "node:fs";
import { isAbsolute, join, resolve } from "node:path";
import { isValidName } from "./refs.ts";

/**
 * Everything `/sec add-from-file` needs that is NOT a terminal: the dotenv parser, the naming
 * rule, and the path/candidate logic. Pure or fs-only, no UI, so all of §12g's invariants
 * that can be checked without a screen are checked by ordinary unit tests.
 *
 * The one thing this module is never given is permission to guess. It reads a file only when
 * handed a path that already passed `inspectPath`, and it enumerates a directory only when
 * `splitPathInput` says the user has typed a separator (§12g F1).
 */

/** One file, no more. A `.env` over a megabyte is a mistake or a payload, not a config file. */
export const MAX_ENV_BYTES = 1024 * 1024;
/** How far into a file to look for a NUL before calling it binary. */
const BINARY_SCAN_BYTES = 8192;
/** Ceiling on rows returned for one directory, so `/usr/bin` cannot build a list of thousands. */
export const MAX_CANDIDATES = 500;

export type AssignmentFlag = "escapes" | "unexpanded";

export interface Assignment {
  /** As written in the file, before lowercasing. */
  key: string;
  value: string;
  line: number;
  flags: AssignmentFlag[];
}

export interface ParsedEnv {
  assignments: Assignment[];
  /** Content lines that did not become an assignment (unterminated quote, empty value, `key:`). */
  skipped: number;
  /** Repeated keys collapsed to the last occurrence. */
  duplicates: number;
}

/**
 * Read a value without interpreting it.
 *
 * Returns null when the line cannot be read as a value at all (an unterminated quote), which the
 * caller counts as skipped rather than guessing at the intended bytes. `doubleQuoted` is returned
 * because only a double-quoted value has escape semantics anywhere in the dotenv family, so only
 * there is a backslash worth flagging.
 */
function readValue(raw: string): { value: string; doubleQuoted: boolean } | null {
  const opener = raw[0];
  if (opener === '"' || opener === "'") {
    const close = raw.indexOf(opener, 1);
    if (close === -1) return null;
    // Anything after the closing quote is ignored: a trailing comment is the only thing that
    // can legally be there, and silently keeping it would corrupt the value.
    return { value: raw.slice(1, close), doubleQuoted: opener === '"' };
  }
  // An inline comment needs whitespace before the `#`, so `KEY=abc#def` keeps its `#`.
  const comment = /\s#/.exec(raw);
  return { value: (comment ? raw.slice(0, comment.index) : raw).trimEnd(), doubleQuoted: false };
}

/**
 * dotenv, deliberately without an expansion engine (§12g F3).
 *
 * Escape sequences and `$VAR` are kept exactly as written and *flagged*, never interpreted. A
 * vault value that quietly differs from what the application reads out of the same file would be
 * worse than a visible marker, and a partial dotenv implementation is a bug farm.
 */
export function parseDotenv(text: string): ParsedEnv {
  const body = text.charCodeAt(0) === 0xfeff ? text.slice(1) : text;
  const assignments: Assignment[] = [];
  const indexOfKey = new Map<string, number>();
  let skipped = 0;
  let duplicates = 0;

  const lines = body.split(/\r?\n/);
  for (let i = 0; i < lines.length; i++) {
    const trimmed = lines[i]!.trim();
    // Blank lines and comments are not "skipped" — nothing was attempted.
    if (!trimmed || trimmed.startsWith("#")) continue;

    // The key is any non-space run before the first `=`, so that names the vault cannot
    // represent (`MY.KEY`, `2FA_TOKEN`) reach the list and are refused *visibly* rather than
    // being filtered out as unparseable.
    const match = /^(?:export\s+)?([^\s=]+)\s*=\s*([\s\S]*)$/.exec(trimmed);
    if (!match) {
      skipped++;
      continue;
    }
    const read = readValue(match[2]!);
    if (!read || !read.value.trim()) {
      skipped++;
      continue;
    }

    const flags: AssignmentFlag[] = [];
    if (read.doubleQuoted && /\\[nrt$"\\]/.test(read.value)) flags.push("escapes");
    if (/\$\{?[A-Za-z_]/.test(read.value)) flags.push("unexpanded");

    const key = match[1]!;
    const assignment: Assignment = { key, value: read.value, line: i + 1, flags };
    const seen = indexOfKey.get(key);
    if (seen === undefined) {
      indexOfKey.set(key, assignments.length);
      assignments.push(assignment);
    } else {
      // Last wins, in place: the row keeps its position, the value is the later one.
      assignments[seen] = assignment;
      duplicates++;
    }
  }

  return { assignments, skipped, duplicates };
}

export interface NameChoice {
  name?: string;
  /** Present only when no name could be derived — the row is then disabled, not renamed. */
  reason?: string;
}

function whyInvalid(base: string): string {
  if (/^[0-9]/.test(base)) return "can't auto-name: starts with a digit";
  if (/^_/.test(base)) return "can't auto-name: starts with an underscore";
  if (/[^a-z0-9_-]/.test(base)) return "can't auto-name: uses characters other than a-z, 0-9, _ or -";
  return "can't auto-name: longer than 64 characters";
}

/**
 * §12g F4: the only transformations are lowercasing and numbering. A name that is still illegal
 * after lowercasing is **refused with a reason**, never repaired — inventing `k_2fa_token` would
 * produce a `{{sec:…}}` the user later cannot explain, when editing the file is the real fix.
 *
 * `taken` carries both the vault's names and the names assigned earlier in this same run, which
 * is what makes the row's name final at list time (§12g F5).
 */
export function chooseName(rawKey: string, taken: ReadonlySet<string>): NameChoice {
  const base = rawKey.toLowerCase();
  if (!isValidName(base)) return { reason: whyInvalid(base) };
  if (!taken.has(base)) return { name: base };
  for (let n = 1; ; n++) {
    const candidate = `${base}${n}`;
    // Suffixing cannot exceed the 64-character cap, so there is a point where numbering fails.
    if (!isValidName(candidate)) return { reason: "can't auto-name: at the 64-character limit" };
    if (!taken.has(candidate)) return { name: candidate };
  }
}

export interface PathSplit {
  /** Absolute, normalized directory to list. */
  dir: string;
  /** The text after the last separator, used as a prefix filter. */
  fragment: string;
  /** Everything up to and including the last separator, as the user typed it. */
  rawPrefix: string;
}

function expandHome(text: string, home: string): string {
  if (text === "~") return home;
  // `~user` is not supported: resolving another user's home needs /etc/passwd, and the case
  // does not arise for "the .env in my repo or my home".
  return text.startsWith("~/") ? home + text.slice(1) : text;
}

function resolveAgainst(text: string, opts: { home: string; cwd: string }): string {
  const expanded = expandHome(text, opts.home);
  return isAbsolute(expanded) ? resolve(expanded) : resolve(opts.cwd, expanded);
}

/** Turn a typed path into the absolute path that would be read. */
export function resolvePathInput(input: string, opts: { home: string; cwd: string }): string {
  return resolveAgainst(input, opts);
}

/**
 * §12g F1, as a function: **null means "the user has not named a starting point yet".**
 *
 * The absence of a `/` is the whole check. Nothing upstream may enumerate a directory when this
 * returns null, which is what makes "no scanning until the user types a path" structural instead
 * of a convention someone can forget.
 */
export function splitPathInput(input: string, opts: { home: string; cwd: string }): PathSplit | null {
  if (!input.includes("/")) return null;
  const cut = input.lastIndexOf("/");
  const rawPrefix = input.slice(0, cut + 1);
  return { dir: resolveAgainst(rawPrefix, opts), fragment: input.slice(cut + 1), rawPrefix };
}

export interface Candidate {
  /** Display name, directories carrying a trailing `/`. */
  name: string;
  dir: boolean;
}

export function listCandidates(dir: string, fragment: string): { candidates: Candidate[]; error?: string } {
  let entries;
  try {
    entries = readdirSync(dir, { withFileTypes: true });
  } catch (err) {
    const code = (err as NodeJS.ErrnoException).code;
    return {
      candidates: [],
      error: code === "ENOENT" ? "no such directory" : code === "EACCES" ? "permission denied" : "cannot read directory",
    };
  }

  const found: Candidate[] = [];
  for (const entry of entries) {
    if (entry.name === "." || entry.name === "..") continue;
    if (!entry.name.startsWith(fragment)) continue;
    let isDir = entry.isDirectory();
    if (!isDir && entry.isSymbolicLink()) {
      // A symlink to a directory should descend; a BROKEN symlink stays listed as a file, so the
      // user finds out from the validation message instead of wondering where it went.
      try {
        isDir = statSync(join(dir, entry.name)).isDirectory();
      } catch {
        isDir = false;
      }
    }
    found.push({ name: isDir ? `${entry.name}/` : entry.name, dir: isDir });
  }
  found.sort((a, b) => (a.dir === b.dir ? a.name.localeCompare(b.name) : a.dir ? -1 : 1));

  // Dotfiles are included by construction — `.env` is the entire point of the feature.
  //
  // `../` is offered only while the fragment is EMPTY. It cannot match a filter, and leaving it
  // in a filtered list made it the first row — which meant Tab's default target on `./.env` was
  // the navigation row, turning a completion into `./../`. Browsing gets the escape hatch;
  // filtering gets only rows that match what was typed.
  const candidates: Candidate[] = dir === "/" || fragment !== "" ? [] : [{ name: "../", dir: true }];
  candidates.push(...found.slice(0, MAX_CANDIDATES));
  return { candidates };
}

export type PathKind = "file" | "dir" | "other" | "missing";

export interface Inspection {
  kind: PathKind;
  error?: string;
}

function hasNulByte(path: string): boolean {
  let fd: number;
  try {
    fd = openSync(path, "r");
  } catch {
    return false;
  }
  try {
    const buf = Buffer.alloc(BINARY_SCAN_BYTES);
    const read = readSync(fd, buf, 0, BINARY_SCAN_BYTES, 0);
    return buf.subarray(0, read).includes(0);
  } finally {
    closeSync(fd);
  }
}

/**
 * §12g F2. Nothing is opened before this says `kind === "file"` with no `error`.
 *
 * The non-regular-file refusal is not tidiness: `/dev/stdin` on a pipe blocks the read forever,
 * which from the user's side is a frozen UI with no way to say what happened.
 */
export function inspectPath(path: string): Inspection {
  let stat;
  try {
    stat = statSync(path);
  } catch {
    return { kind: "missing" };
  }
  if (stat.isDirectory()) return { kind: "dir" };
  if (!stat.isFile()) return { kind: "other", error: "not a file" };
  if (stat.size > MAX_ENV_BYTES) return { kind: "file", error: "too large — is this really a .env?" };
  if (hasNulByte(path)) return { kind: "file", error: "not a text file" };
  return { kind: "file" };
}
