import { createBashToolDefinition, type ExtensionAPI, type ToolDefinition } from "@earendil-works/pi-coding-agent";
import { fileURLToPath } from "node:url";
import type { Vault } from "../vault.ts";
import { injectBashCommand } from "../glue.ts";
import { scrubText } from "../scrub.ts";
import { isEnabled } from "../state.ts";

type BashDef = ReturnType<typeof createBashToolDefinition>;
type ExecuteFn = BashDef["execute"];
type OnUpdate = Parameters<ExecuteFn>[3];
type UpdateFn = NonNullable<OnUpdate>;

export interface SecureBashOptions {
  vault: () => Vault;
  /** Test seam: observe the expanded command and env before exec. */
  onExpand?: (command: string, env: Record<string, string>) => void;
}

/** One streamed partial: only text blocks carry output that could hold a secret. */
function scrubPartial(partial: unknown, vault: Vault): unknown {
  if (!partial || typeof partial !== "object") return partial;
  const record = partial as { content?: unknown };
  if (!Array.isArray(record.content)) return partial;
  return {
    ...(partial as Record<string, unknown>),
    content: record.content.map((block) => {
      if (!block || typeof block !== "object") return block;
      const b = block as { type?: unknown; text?: unknown };
      if (b.type !== "text" || typeof b.text !== "string") return block;
      return { ...(block as Record<string, unknown>), text: scrubText(b.text, vault, { shapes: true }).text };
    }),
  };
}

/**
 * pi streams bash output through `onUpdate` as `tool_execution_update`, straight to
 * the renderer; `tool_result` only fires at the end. So a command that echoes a
 * secret — `printf %s {{sec:gh_pat}}`, or any CLI dumping its own config — prints it
 * on screen mid-turn even though the final result is masked. Wrap `execute` to scrub
 * those partials; the spawnHook still owns expansion, so this only observes output.
 */
function withScrubbedUpdates(def: BashDef, getVault: () => Vault): BashDef {
  const execute = def.execute.bind(def) as ExecuteFn;
  const executeWrapped: ExecuteFn = (toolCallId, params, signal, onUpdate, ctx) => {
    const update: UpdateFn | undefined =
      typeof onUpdate === "function" ? (partial) => onUpdate(scrubPartial(partial, getVault()) as never) : undefined;
    return execute(toolCallId, params, signal, update, ctx);
  };
  return { ...def, execute: executeWrapped };
}

export function createSecureBashToolDefinition(cwd: string, options: SecureBashOptions): BashDef {
  const def = createBashToolDefinition(cwd, {
    // The hook sees the ORIGINAL command text (refs intact) because tool_call
    // deliberately does not mutate bash input. Spreading env keeps it per-call:
    // parallel bash children never see each other's secrets, and process.env is
    // never touched.
    spawnHook: (spawnCtx) => {
      // `/sec off` says "refs will not expand". Bash is the one injection path that
      // never goes through the isEnabled()-gated `tool_call` hook, so without this
      // check the whole mechanism kept working after the user switched it off —
      // for the single path that matters most. Blocking is deliberate: silently
      // skipping substitution would run `curl -H "Bearer {{sec:gh}}"` and report
      // success, and a literal placeholder read back as a working credential is the
      // false-confidence class this design treats as its worst failure.
      if (!isEnabled() && /\{\{sec:[a-z][a-z0-9_-]{0,63}\}\}/.test(spawnCtx.command)) {
        throw new Error(
          "pi-secure is disabled for this session, so {{sec:…}} refs are not expanded. Run /sec on to re-enable them.",
        );
      }
      const expansion = injectBashCommand(spawnCtx.command, options.vault());
      // A non-empty `block` means at least one ref was NOT substituted, so the
      // command would run with a literal `{{sec:…}}` in it. Throw rather than
      // spawn; pi surfaces `message` as the tool error the model reads, and the
      // two reasons stay distinguishable — "name not found" is a model error it
      // can fix by listing names, while an unexpandable context is a quoting
      // problem.
      if (expansion.block) throw new Error(expansion.block.reason);
      if (!expansion.expanded.length) return spawnCtx;
      options.onExpand?.(expansion.command, expansion.env);
      return { ...spawnCtx, command: expansion.command, env: { ...spawnCtx.env, ...expansion.env } };
    },
  }) as BashDef;

  return withScrubbedUpdates(def, options.vault);
}

export function registerSecureBash(pi: ExtensionAPI, cwd: string, options: SecureBashOptions): void {
  // createBashToolDefinition already carries promptSnippet, promptGuidelines,
  // renderCall and renderResult, so registering it preserves built-in presentation.
  pi.registerTool(createSecureBashToolDefinition(cwd, options) as unknown as ToolDefinition);
}

/**
 * Our own package directory, computed from this module's URL rather than assumed from
 * the package name: this file is `<pkg>/src/tools/bash.ts`, so one level up is
 * `<pkg>/src` — the directory pi reports as an extension's `sourceInfo.baseDir`.
 */
const OUR_PACKAGE_SRC_DIR = fileURLToPath(new URL("..", import.meta.url)).replace(/\/$/, "");

/**
 * Did our `bash` actually win?
 *
 * Verified in pi source: extension tools DO replace built-ins, but among *extensions*
 * the first registration of a name wins, so another loaded extension that also registers
 * `bash` can beat us silently. That failure mode is invisible — refs would then reach
 * the child as literal `{{sec:…}}` text with no error from pi at all — so it is
 * detected explicitly and Task 10 turns a false result into a loud notify().
 * `source !== "builtin"` alone is NOT enough: a rival extension's tool carries
 * `source: "extension"` too.
 *
 * The decision is PATH IDENTITY, not a substring test. pi stamps every extension's
 * tools with that extension's own sourceInfo, whose `baseDir` is the directory of the
 * resolved entry file (extensions/loader.js:444-449), so comparing it against this
 * module's own package directory is exact in both directions:
 *  - a renamed or relocated install still matches, because both sides move together.
 *    A `/pi-secure/` substring test reported "not ours" for any install outside a
 *    directory named pi-secure, which is a nag on every session for no security gain.
 *  - a DIFFERENT extension whose path merely CONTAINS the substring "pi-secure" (a
 *    fork at `.../pi-secure-fork/`, or a name chosen to defeat this check) does not
 *    match. This is the direction that matters: matching it would suppress the very
 *    warning that exists, which is the silent-insecure-success case.
 *
 * A synthetic path (`<builtin:...>`-style, no baseDir) falls back to the historical
 * substring check, so behaviour on those shapes is unchanged. Fail-safe overall: a
 * wrong "not ours" produces a loud notify, never a silent insecure success.
 */
export function bashIsOwnedByPiSecure(pi: ExtensionAPI): boolean {
  const effective = pi.getAllTools().find((t) => t.name === "bash");
  if (!effective || effective.sourceInfo.source === "builtin") return false;
  const { path, baseDir } = effective.sourceInfo;
  if (typeof baseDir === "string" && baseDir.length > 0) return baseDir === OUR_PACKAGE_SRC_DIR;
  return /pi-secure/.test(path);
}
