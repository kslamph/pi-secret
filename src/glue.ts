import { readFileSync, renameSync, unlinkSync, writeFileSync } from "node:fs";
import type { Vault } from "./vault.ts";
import { bashRefIssues, expandBash, expandRefs, findRefs } from "./substitute.ts";
import { redactAllText, scrubDeep, scrubText } from "./scrub.ts";
import { applyCapture, findCandidates, suggestNames, type CapturedItem } from "./capture.ts";

import { MIN_SCRUBABLE_LENGTH, RESERVED_NAME } from "./refs.ts";

const BLOCKED_IN_PATH = new Set(["read", "grep", "find", "ls"]);
const PRESERVED_DETAIL_KEYS: ReadonlySet<string> = new Set(["fullOutputPath"]);
const BLOCKED_IN_CONTENT = new Set(["write", "edit"]);

export interface ToolCallLike {
  toolName: string;
  input: Record<string, unknown>;
}

export interface InjectOutcome {
  blocked?: { reason: string };
  /** §12h: user-only notice for deliberate allows (doc/test targets). Never model-facing. */
  notify?: string;
  expanded: string[];
  env: Record<string, string>;
}

const FILE_WRITE_REASON =
  "sec refs are not written to files (the literal text would be stored, not the value). " +
  "Materializing secrets into files is out of scope. If this value came from a scrubbed " +
  "tool result, tell the user where it needs to go and let them place it.";

/*
 * §12h: where quoting the ref SYNTAX is the norm, so the write gate must not fire.
 *
 * The guard is a correctness tripwire, not a boundary — the model can assemble the
 * literal at runtime and always could. What it actually catches is a masked value
 * being persisted into a file a consumer expects to hold a real credential, and that
 * mistake always resolves in the vault, or is the scrubber's reserved marker.
 * Documentation, tests, fixtures and templates quote the syntax on purpose; a name
 * that stores nothing cannot be a persisted value.
 */
const DOC_SEGMENT_RE = /(?:^|\/)(?:docs?|tests?|fixtures?|examples?)(?:\/|$)/i;
const DOC_SUFFIX_RE = /\.(?:markdown|md|example|sample|template)$/i;

/** Is this target documentation/test/fixture/template territory (§12h)? */
export function isDocPath(path: string): boolean {
  // Whole path segments only: `mydocs/x.env` and `testing/x` stay real targets,
  // because the segment must be bounded by start-or-slash on both sides.
  return DOC_SEGMENT_RE.test(path) || DOC_SUFFIX_RE.test(path);
}

interface RefHit {
  container: Record<string, unknown> | unknown[];
  key: string | number;
  name: string;
}

function deepFindRefs(value: unknown, hits: RefHit[] = []): RefHit[] {
  if (Array.isArray(value)) {
    // Strings inside arrays are leaves too: headers: ["a", "{{sec:x}}"] must expand.
    for (let i = 0; i < value.length; i++) {
      const item = value[i];
      if (typeof item === "string") {
        for (const r of findRefs(item)) hits.push({ container: value, key: i, name: r.name });
      } else {
        deepFindRefs(item, hits);
      }
    }
    return hits;
  }
  if (value && typeof value === "object") {
    for (const [k, v] of Object.entries(value)) {
      if (typeof v === "string") {
        for (const r of findRefs(v)) hits.push({ container: value as Record<string, unknown>, key: k, name: r.name });
      } else {
        deepFindRefs(v, hits);
      }
    }
  }
  return hits;
}

export function injectBashCommand(
  command: string,
  vault: Vault,
): { command: string; env: Record<string, string>; expanded: string[]; block?: { reason: string } } {
  const issues = bashRefIssues(command, vault);
  if (issues.length) {
    return { command, env: {}, expanded: [], block: { reason: issues[0]!.problem } };
  }
  const out = expandBash(command, (name) => vault.resolve(name));
  // Defense in depth. `expandBash` is the component that actually knows whether a
  // ref got substituted; the guard is a lexical pre-pass that has to be kept in
  // sync with it. Today they agree, but Task 15 phase 2 adds new lexical contexts
  // and a single disagreement would mean spawning with a literal `{{sec:…}}` —
  // the model would read that back as "$VAR" and try to "fix" it by asking the
  // user for the token, which is the one path this project exists to close.
  if (out.missing.length) {
    return {
      command,
      env: {},
      expanded: [],
      block: {
        reason:
          `could not expand sec:${out.missing.join(", ")} — this shell context cannot deliver the value. ` +
          "Move the ref outside it, or pass it through an environment variable instead.",
      },
    };
  }
  return { command: out.command, env: out.env, expanded: out.used };
}

/**
 * Vaulted VALUES (not refs) appearing literally in a tool's arguments.
 *
 * The model is not supposed to ever hold a value — that is the entire contract —
 * so a literal here means something already leaked upstream (most likely a
 * `read` of a credential file with shape masking off, spec §12.13). When that
 * happens the honest response is to refuse rather than to help: a value the model
 * can see is a value it can write to disk, paste into a URL, or echo into a
 * transcript. Returning the ref form keeps the command usable while putting the
 * value back where it belongs — the child environment.
 */
function literalSecretNames(vault: Vault, input: Record<string, unknown>): string[] {
  const serialized = JSON.stringify(input) ?? "";
  const names: string[] = [];
  for (const value of vault.values()) {
    if (value.length < MIN_SCRUBABLE_LENGTH) continue;
    if (!serialized.includes(value)) continue;
    const name = vault.findByValue(value)?.name;
    if (name && !names.includes(name)) names.push(name);
  }
  return names;
}

export function injectToolCall(toolName: string, input: Record<string, unknown>, vault: Vault): InjectOutcome {
  const literals = literalSecretNames(vault, input);
  if (literals.length) {
    return {
      blocked: {
        reason: BLOCKED_IN_CONTENT.has(toolName)
          ? `${FILE_WRITE_REASON} A vaulted value (sec:${literals.join(", ")}) was also passed literally.`
          : `sec:${literals.join(", ")} was passed as a literal value. Reference it as {{sec:${literals[0]}}} instead — pi-secret substitutes it at execution time, so the value never enters the command, the transcript, or the session file.`,
      },
      expanded: [],
      env: {},
    };
  }
  if (BLOCKED_IN_PATH.has(toolName)) {
    const serialized = JSON.stringify(input) ?? "";
    if (findRefs(serialized).length) {
      return {
        blocked: { reason: `sec: refs are not a valid path or pattern for ${toolName}.` },
        expanded: [],
        env: {},
      };
    }
  }
  if (BLOCKED_IN_CONTENT.has(toolName)) {
    // §12h order: an address is never syntax; then the target class; then whether
    // the ref could actually be a persisted value. Every allow returns BEFORE the
    // expansion loop — substituting into a doc would create the one file on disk
    // that holds the value.
    const path = typeof input.path === "string" ? input.path : "";
    if (findRefs(path).length) {
      return {
        blocked: {
          reason:
            "a sec ref cannot be a file path — the literal placeholder would NAME the file, not deliver the value.",
        },
        expanded: [],
        env: {},
      };
    }
    const contentOnly = JSON.stringify(
      Object.fromEntries(Object.entries(input).filter(([k]) => k !== "path")),
    );
    const refs = findRefs(contentOnly ?? "");
    if (refs.length) {
      if (isDocPath(path)) {
        const n = refs.length;
        return {
          expanded: [],
          env: {},
          notify:
            `pi-secret: ${n} sec ref${n === 1 ? "" : "s"} written literally to ${path} — ` +
            "documentation/test target: names only, no values were substituted.",
        };
      }
      const resolving = refs.filter((r) => vault.has(r.name));
      if (resolving.length) {
        return {
          blocked: {
            reason:
              FILE_WRITE_REASON +
              ` (sec:${resolving.map((r) => r.name).join(", ")} resolves in this session's vault)`,
          },
          expanded: [],
          env: {},
        };
      }
      // The scrubber's own marker is never prose in a real target: it means a
      // masked value — not a stored one, so it did not trip `resolving` — is on
      // its way into a file. The canary for this is a shape-masked token read
      // back from a tool result and dutifully persisted. Documentation may quote
      // the marker (the spec does); anything else may not.
      if (refs.some((r) => r.name === RESERVED_NAME)) {
        return {
          blocked: {
            reason:
              "this text carries the scrubber's marker (sec:redacted): it came out of a masked " +
              "result, and writing it stores the placeholder, not the value. Tell the user where " +
              "the value needs to go and let them place it. (Quoting the marker as prose? Doc and " +
              "test targets allow it; or quote a different placeholder name.)",
          },
          expanded: [],
          env: {},
        };
      }
      // Non-resolving prose in a non-doc target: quoting syntax nobody stores.
      return { expanded: [], env: {} };
    }
  }
  // bash is owned by the wrapped tool's spawnHook (Task 9). It must see the
  // ORIGINAL ref text — mutating it here would double-expand and drop the env.
  if (toolName === "bash") return { expanded: [], env: {} };
  const refs = deepFindRefs(input);
  if (!refs.length) return { expanded: [], env: {} };
  const resolve = (name: string): string | undefined => vault.resolve(name);
  const expanded: string[] = [];
  for (const hit of refs) {
    const slot = (hit.container as Record<string | number, unknown>)[hit.key] as string;
    const next = expandRefs(slot, resolve);
    (hit.container as Record<string | number, unknown>)[hit.key] = next.text;
    for (const n of next.used) if (!expanded.includes(n)) expanded.push(n);
  }
  return { expanded, env: {} };
}

export interface ScrubOutcome {
  content: unknown[];
  details?: unknown;
  hits: number;
}

export function scrubToolResult(
  event: { toolName: string; content: unknown[]; details?: unknown },
  vault: Vault,
  opts: { fileReads: boolean },
): ScrubOutcome {
  // Shape masking stays off for read/grep/find/ls unless the caller enabled it for
  // file reads — a source file containing `password=` would otherwise be corrupted.
  // Value-exact masking always applies.
  const applyShapes = opts.fileReads || !/^(?:read|grep|find|ls)$/.test(event.toolName);
  try {
    const content = scrubDeep(event.content, vault, { shapes: applyShapes });
    // fullOutputPath is a POINTER, not model-facing text: masking it would strand the
    // unsanitised snapshot on disk (see ScrubOptions.preserveKeys).
    const details =
      event.details === undefined
        ? undefined
        : scrubDeep(event.details, vault, { shapes: applyShapes, preserveKeys: PRESERVED_DETAIL_KEYS });
    return {
      content: content.value as unknown[],
      details: details?.value,
      hits: content.hits + (details?.hits ?? 0),
    };
  } catch {
    // Fail closed (§11): an unverified block must not reach the model or the log.
    const masked = event.content.map((block) =>
      block && typeof block === "object" && "text" in block
        ? { ...(block as Record<string, unknown>), text: "{{sec:redacted}}" }
        : block,
    );
    return { content: masked, details: undefined, hits: 0 };
  }
}

export function scrubMessageText(text: string, vault: Vault, opts: { shapes: boolean }): string {
  try {
    return scrubText(text, vault, opts).text;
  } catch {
    return "{{sec:redacted}}";
  }
}

/**
 * scrubDeep with the §11 fail-closed fallback, for the hooks that guard the two
 * surfaces pi hands back UNCHANGED when a handler throws.
 *
 * Why this wrapper exists: `emitMessageEnd`, `emitContext` and
 * `emitBeforeProviderRequest` in pi's ExtensionRunner each wrap every handler in
 * try/catch, call `emitError`, and return the value they held before the failing
 * handler ran. So for those three hooks an exception is not a crash — it is a silent
 * skip of scrubbing, on the persisted assistant message and on the exact bytes sent
 * to the provider. `scrubToolResult` was already guarded; these were not, which is
 * the asymmetry a 2026-10-08 review found.
 *
 * The fallback over-redacts (every string becomes the marker). That is the intended
 * asymmetry: losing the model's context costs a turn, leaking the credential costs
 * the user. `onError` gets the error CLASS only — never its message — because a
 * thrown message can carry the very text that failed to scrub.
 */
export function scrubDeepFailClosed<T>(
  value: T,
  vault: Vault,
  opts: { shapes: boolean },
  onError?: (errorClass: string) => void,
): { value: T; hits: number } {
  try {
    return scrubDeep(value, vault, opts);
  } catch (error) {
    onError?.(
      error instanceof Error ? error.constructor.name : typeof error,
    );
    return { value: redactAllText(value), hits: 1 };
  }
}

/**
 * pi's bash truncation writes raw output to `details.fullOutputPath`. Rewrite that
 * file scrubbed in place; on ANY failure unlink it and DELETE the pointer — a stale
 * pointer to content we could not clean is worse than no pointer.
 */
export function scrubOutputSnapshot(details: unknown, vault: Vault): void {
  if (!details || typeof details !== "object") return;
  const record = details as Record<string, unknown>;
  const path = record.fullOutputPath;
  if (typeof path !== "string" || !path) return;
  try {
    const raw = readFileSync(path, "utf8");
    const scrubbed = scrubText(raw, vault, { shapes: true }).text;
    writeFileSync(path, scrubbed);
  } catch {
    try {
      unlinkSync(path);
    } catch {
      // Already gone — the pointer must still be dropped.
    }
    delete record.fullOutputPath;
  }
}

export interface CaptureReceipt {
  name: string;
  fingerprint: string;
  /** Human-recognisable label: `ghp_A1b2…Q7R8`, or the digest for a short value. */
  label: string;
  length: number;
  source: "paste";
}

export function captureFromText(
  text: string,
  vault: Vault,
): { text: string; captured: CaptureReceipt[] } {
  const candidates = findCandidates(text);
  if (!candidates.length) return { text, captured: [] };
  let names: string[];
  try {
    names = suggestNames(candidates, text, {
      taken: vault.names(),
      existingNameForValue: (value) => vault.findByValue(value)?.name,
    });
  } catch {
    // A suggestion bug must never cost the user their paste.
    return { text, captured: [] };
  }
  const items: CapturedItem[] = candidates.map((candidate, i) => ({ candidate, name: names[i]! }));
  const out = applyCapture(text, items);
  // Vault ONLY what applyCapture actually substituted — never a skipped name.
  const captured: CaptureReceipt[] = [];
  for (const item of out.captured) {
    try {
      const entry = vault.add(item.name, item.candidate.value, "paste");
      captured.push({
        name: entry.name,
        fingerprint: entry.fingerprint,
        label: entry.preview ?? `sha256:${entry.fingerprint}`,
        length: entry.length,
        source: "paste",
      });
    } catch {
      // A name the vault refuses (invalid, or colliding shell variable) must not
      // leave a ref sitting in the user's message pointing at nothing: they would
      // submit text referring to a secret that does not exist. Fall back to the
      // ORIGINAL text and report no capture — the safe direction is "nothing was
      // protected and nothing was claimed", never a dangling ref or a false receipt.
      return { text, captured: [] };
    }
  }
  return { text: out.text, captured };
}

/**
 * pi persists a compaction summary through `sessionManager.appendCompaction()`, which
 * writes a `type: "compaction"` entry straight to the session JSONL. That summary is
 * MODEL-AUTHORED text, and it is the one such text that never passes through
 * `message_end` — so nothing in this extension ever sees it before it lands on disk.
 * Measured (2026-10-08): a summary that repeats a vaulted value writes that value
 * verbatim into the session file, and it survives every later turn, `/export` and
 * `/resume`.
 *
 * The wire is safe — `context` and `before_provider_request` both scrub on the way out —
 * but the file is the transcript of record, and a compaction summary is precisely the
 * text that outlives the turn that produced it.
 *
 * So this amends the one entry, in place, and only when there is something to amend:
 * hits === 0 returns immediately, so the overwhelmingly common case does not touch the
 * user's session file at all.
 *
 * Safety, in order: the original content is held in memory, the rewrite goes to a temp
 * file and is renamed over the target (pi appends with `appendFileSync(path)`, which
 * reopens by path, so the inode swap is safe), and the result is re-read and verified.
 * Any failure restores the original bytes and reports, because a half-written session
 * file is worse than a leaky one.
 */
export function scrubCompactionSummaryFile(
  file: string,
  entryId: string,
  vault: Vault,
): { rewritten: boolean; hits: number } {
  let original: string;
  try {
    original = readFileSync(file, "utf8");
  } catch {
    return { rewritten: false, hits: 0 };
  }
  const lines = original.split("\n");
  let hits = 0;
  let touched = false;
  const out = lines.map((line) => {
    if (!line.trim()) return line;
    let entry: Record<string, unknown>;
    try {
      entry = JSON.parse(line) as Record<string, unknown>;
    } catch {
      return line; // header or a partial line: never ours to touch
    }
    if (entry.type !== "compaction" || entry.id !== entryId || typeof entry.summary !== "string") return line;
    const scrubbed = scrubText(entry.summary, vault, { shapes: true });
    if (!scrubbed.hits) return line;
    hits += scrubbed.hits;
    touched = true;
    return JSON.stringify({ ...entry, summary: scrubbed.text });
  });
  if (!touched) return { rewritten: false, hits: 0 };

  const tmp = `${file}.pisec-tmp`;
  try {
    writeFileSync(tmp, out.join("\n"));
    renameSync(tmp, file);
  } catch {
    try {
      unlinkSync(tmp);
    } catch {
      /* best effort */
    }
    try {
      writeFileSync(file, original);
    } catch {
      /* the rename already failed, so the original is still in place */
    }
    return { rewritten: false, hits };
  }
  // Verify: a session file that silently lost an entry is a catastrophic outcome, and
  // the only way to know is to read it back.
  try {
    const check = readFileSync(file, "utf8");
    const entry = check
      .split("\n")
      .map((l) => {
        try {
          return JSON.parse(l) as Record<string, unknown>;
        } catch {
          return null;
        }
      })
      .find((e) => e?.type === "compaction" && e.id === entryId);
    const summary = entry?.summary;
    const ok =
      typeof summary === "string" &&
      check.split("\n").filter((l) => l.trim()).length === lines.filter((l) => l.trim()).length;
    if (!ok) throw new Error("verification failed");
  } catch {
    writeFileSync(file, original);
    return { rewritten: false, hits };
  }
  return { rewritten: true, hits };
}
