import { readFileSync, realpathSync, unlinkSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { resolve as resolvePath } from "node:path";
import type { Vault } from "./vault.ts";
import { bashRefIssues, expandBash, expandRefs, findRefs } from "./substitute.ts";
import { redactAllText, scrubDeep, scrubText, type ShapeAdopter, type ShapeHit } from "./scrub.ts";
import { applyCapture, findCandidates, suggestNames, type CapturedItem } from "./capture.ts";

import { MIN_SCRUBABLE_LENGTH, RESERVED_NAME, isValidName } from "./refs.ts";

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

/**
 * The path a file tool will actually touch, in one canonical form, so a `read` origin and a
 * later `write` target compare equal however the model spelled them. Mirrors pi's own
 * resolveToCwd (leading `@` stripped, `~` expanded, relative to cwd) and then follows
 * symlinks when the file exists, so `./.env` and a symlink to it are one file.
 */
export function canonicalPath(path: string, cwd: string): string {
  let p = path.startsWith("@") ? path.slice(1) : path;
  if (p === "~") p = homedir();
  else if (p.startsWith("~/")) p = homedir() + p.slice(1);
  const abs = resolvePath(cwd, p);
  try {
    return realpathSync(abs);
  } catch {
    return abs;
  }
}

/**
 * After a `read`, remember which vaulted values that file really contains (spec §12j).
 *
 * Checked against the RAW tool output, before scrubbing, and only for the literal value: a
 * file that merely quotes `{{sec:x}}` as text, or holds an encoding of it, does not count,
 * because expanding a ref there would put the value somewhere it never was. Call it after
 * scrubbing, so a credential adopted from this same read is already in the vault.
 */
export function recordReadOrigins(
  event: { toolName: string; input: Record<string, unknown>; content: unknown[] },
  vault: Vault,
  cwd: string,
): void {
  if (event.toolName !== "read" || typeof event.input.path !== "string") return;
  const raw = event.content
    .map((b) => (b && typeof b === "object" && typeof (b as { text?: unknown }).text === "string" ? (b as { text: string }).text : ""))
    .join("\n");
  if (!raw) return;
  const target = canonicalPath(event.input.path, cwd);
  for (const value of vault.values()) {
    if (value.length < MIN_SCRUBABLE_LENGTH || !raw.includes(value)) continue;
    const name = vault.findByValue(value)?.name;
    if (name) vault.addOrigin(name, target);
  }
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
    const entry = vault.findByValue(value);
    // An adopted value was only ever shown to the model as a ref. If the model types it
    // anyway, it knew it already (AWS's documented `AKIAIOSFODNN7EXAMPLE` is the usual
    // case, adopted from a docs page and then written into a test fixture). Blocking that
    // would refuse ordinary work over a value that came from the endpoint, not from us.
    if (!entry || entry.source === "output") continue;
    if (!names.includes(entry.name)) names.push(entry.name);
  }
  return names;
}

export function injectToolCall(
  toolName: string,
  input: Record<string, unknown>,
  vault: Vault,
  opts: { cwd?: string } = {},
): InjectOutcome {
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
      const doc = isDocPath(path);
      const resolving = refs.filter((r) => vault.has(r.name));
      // §12j: a ref whose value was READ from this very file may be written back to it.
      // That is what makes `read .env` → `edit .env` work when the file holds credentials:
      // the value goes back where it was and nowhere else, so nothing new lands on disk.
      const target = opts.cwd && path ? canonicalPath(path, opts.cwd) : undefined;
      const restorable = new Set(
        target ? resolving.filter((r) => vault.hasOrigin(r.name, target)).map((r) => r.name) : [],
      );
      const stranded = [...new Set(resolving.filter((r) => !restorable.has(r.name)).map((r) => r.name))];
      if (doc && !restorable.size) {
        const n = refs.length;
        return {
          expanded: [],
          env: {},
          notify:
            `pi-secret: ${n} sec ref${n === 1 ? "" : "s"} written literally to ${path} — ` +
            "documentation/test target: names only, no values were substituted.",
        };
      }
      if (stranded.length && !doc) {
        return {
          blocked: {
            reason:
              FILE_WRITE_REASON +
              ` (sec:${stranded.join(", ")} resolves in this session's vault)` +
              (restorable.size
                ? ` Only a ref read from this same file can be written back to it (sec:${[...restorable].join(", ")} can).`
                : ""),
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
      if (!doc && refs.some((r) => r.name === RESERVED_NAME)) {
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
      if (restorable.size) {
        // Expand ONLY the restorable names, and never in `path`. Anything else stays literal:
        // non-resolving prose, and (in a doc target) a stranded name, exactly as before.
        const expanded: string[] = [];
        const resolveRestorable = (name: string): string | undefined =>
          restorable.has(name) ? vault.resolve(name) : undefined;
        for (const [key, value] of Object.entries(input)) {
          if (key === "path") continue;
          if (typeof value === "string") {
            const next = expandRefs(value, resolveRestorable);
            input[key] = next.text;
            for (const n of next.used) if (!expanded.includes(n)) expanded.push(n);
            continue;
          }
          for (const hit of deepFindRefs(value)) {
            const slot = (hit.container as Record<string | number, unknown>)[hit.key] as string;
            const next = expandRefs(slot, resolveRestorable);
            (hit.container as Record<string | number, unknown>)[hit.key] = next.text;
            for (const n of next.used) if (!expanded.includes(n)) expanded.push(n);
          }
        }
        return {
          expanded,
          env: {},
          notify: `pi-secret: wrote sec:${expanded.join(", ")} back into ${path}, the file ${expanded.length === 1 ? "it was" : "they were"} read from`,
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

/**
 * The most credentials one session will adopt from output. Past it, a shape match falls back
 * to the generic marker, so a huge dump of keys cannot grow the vault (and the per-string value
 * pass, which scales with vault size) without bound. Still masked either way.
 */
export const MAX_ADOPTED = 64;

function adoptedName(hit: ShapeHit, taken: ReadonlySet<string>): string | undefined {
  const raw =
    hit.kind === "kv" ? hit.key : hit.kind === "provider" ? hit.hint : hit.kind === "pem" ? "private_key" : "jwt";
  let base = (raw ?? "secret").toLowerCase().replace(/[^a-z0-9]+/g, "_").replace(/^_+|_+$/g, "").slice(0, 56);
  if (!base) base = "secret";
  if (!/^[a-z]/.test(base)) base = `s_${base}`;
  if (base === RESERVED_NAME) base = "secret";
  for (let n = 1; n < 1000; n++) {
    const name = n === 1 ? base : `${base}-${n}`;
    if (isValidName(name) && !taken.has(name)) return name;
  }
  return undefined;
}

/**
 * The adopter every scrub path with a vault uses (see ScrubOptions.adopt).
 *
 * Idempotent by value: a value already in the vault, whoever put it there, keeps its name, so
 * the streaming display, the final tool result, the snapshot file and every later `context`
 * pass all agree on one ref. `onAdopt` is told only about names that are NEW, which is what
 * the caller announces to the user.
 */
export function vaultAdopter(vault: Vault, onAdopt?: (name: string) => void): ShapeAdopter {
  return (hit) => {
    const existing = vault.findByValue(hit.value);
    if (existing) return existing.name;
    if (vault.entries().filter((e) => e.source === "output").length >= MAX_ADOPTED) return undefined;
    const name = adoptedName(hit, new Set(vault.names()));
    if (name === undefined) return undefined;
    try {
      vault.add(name, hit.value, "output");
    } catch {
      // Refused (shell-variable collision, oversize). Masked with the marker instead: the
      // one thing this must never do is leave the value visible.
      return undefined;
    }
    onAdopt?.(name);
    return name;
  };
}

export interface ScrubOutcome {
  content: unknown[];
  details?: unknown;
  hits: number;
  /**
   * Binary payloads left untouched (image/audio blocks, long base64 runs). Counted so
   * the caller can tell the user, because "nothing was masked" and "we could not mask
   * a screenshot" look identical from the outside — and only one of them is true.
   */
  skippedBinary: number;
}

export function scrubToolResult(
  event: { toolName: string; content: unknown[]; details?: unknown },
  vault: Vault,
  opts: { fileReads: boolean; adopt?: ShapeAdopter },
): ScrubOutcome {
  // Shape masking stays off for read/grep/find/ls unless the caller enabled it for
  // file reads — a source file containing `password=` would otherwise be corrupted.
  // Value-exact masking always applies.
  const applyShapes = opts.fileReads || !/^(?:read|grep|find|ls)$/.test(event.toolName);
  try {
    const content = scrubDeep(event.content, vault, { shapes: applyShapes, adopt: opts.adopt });
    // fullOutputPath is a POINTER, not model-facing text: masking it would strand the
    // unsanitised snapshot on disk (see ScrubOptions.preserveKeys).
    const details =
      event.details === undefined
        ? undefined
        : scrubDeep(event.details, vault, { shapes: applyShapes, preserveKeys: PRESERVED_DETAIL_KEYS, adopt: opts.adopt });
    return {
      content: content.value as unknown[],
      details: details?.value,
      hits: content.hits + (details?.hits ?? 0),
      skippedBinary: content.skippedBinary + (details?.skippedBinary ?? 0),
    };
  } catch {
    // Fail closed (§11): an unverified block must not reach the model or the log.
    // Note the payload blocks are passed through rather than blanked — a fail-closed
    // image is a corrupt image, and corrupt is how this whole bug started.
    const masked = event.content.map((block) =>
      block && typeof block === "object" && "text" in block
        ? { ...(block as Record<string, unknown>), text: "{{sec:redacted}}" }
        : block,
    );
    return { content: masked, details: undefined, hits: 0, skippedBinary: 0 };
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
  opts: { shapes: boolean; adopt?: ShapeAdopter },
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
export function scrubOutputSnapshot(details: unknown, vault: Vault, adopt?: ShapeAdopter): void {
  if (!details || typeof details !== "object") return;
  const record = details as Record<string, unknown>;
  const path = record.fullOutputPath;
  if (typeof path !== "string" || !path) return;
  try {
    const raw = readFileSync(path, "utf8");
    const scrubbed = scrubText(raw, vault, { shapes: true, adopt }).text;
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
  /**
   * Why this was captured, when the reason is a judgement rather than a format.
   *
   * Absent for a keyword or provider-format hit, where the reason is self-evident from
   * the name. Present for a shape-only capture, and deliberately so: a receipt that said
   * only `sec:secret · len 21` is what made the 2026-10-09 over-capture impossible to
   * diagnose after the fact.
   */
  evidence?: string;
}

/** Which candidates a capture may apply. "evidenced" drops every shape-only guess. */
export type CaptureScope = "all" | "evidenced";

/**
 * The shape-only candidates in `text` — everything found on appearance alone.
 *
 * Split out from captureFromText because the CONFIRM decision has to be made before
 * anything is rewritten: the user has to see the guesses and answer before the sentence
 * they are in is modified, and by then findCandidates has already run.
 */
export function findGuesses(text: string) {
  return findCandidates(text).filter((c) => c.confidence === "entropy");
}

export function captureFromText(
  text: string,
  vault: Vault,
  opts: { scope?: CaptureScope } = {},
): { text: string; captured: CaptureReceipt[] } {
  let candidates = findCandidates(text);
  if (opts.scope === "evidenced") candidates = candidates.filter((c) => c.confidence !== "entropy");
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
        evidence: item.candidate.evidence,
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
