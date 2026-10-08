import { createBashToolDefinition, type ExtensionAPI, type ToolDefinition } from "@earendil-works/pi-coding-agent";
import { realpathSync } from "node:fs";
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
          "pi-secret is disabled for this session, so {{sec:…}} refs are not expanded. Run /sec on to re-enable them.",
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


/**
 * Identity by FILE, not by directory or by substring.
 *
 * Node resolves a module to its real path, so `import.meta.url` here is the checkout,
 * while pi reports whatever path it loaded the extension FROM. Under `pi install <path>`
 * those differ: pi creates a link under the agent dir, Node resolves through it, and the two
 * strings never match. An earlier version compared directories and fell back to matching
 * /pi-secret/ in the path when `baseDir` was absent — which is most of the time, since pi's
 * synthetic sourceInfo for a file-loaded extension carries path/source/scope/origin and no
 * baseDir. The result was a warning on every symlinked install telling the user their refs
 * would not expand while they were expanding perfectly well. A field report, not a theory.
 *
 * So: realpath both sides and compare the extension ENTRY file. That is exact for every
 * install layout — renamed directory, package cache, symlink, relocated checkout — and it
 * cannot be spoofed by a path that merely looks like ours.
 */
const OUR_ENTRY = resolveRealPath(fileURLToPath(new URL("../index.ts", import.meta.url)));

/** realpath with a fallback to the input, so an unreadable path degrades instead of throwing. */
function resolveRealPath(p: string): string {
  try {
    return realpathSync(p);
  } catch {
    return p;
  }
}

/**
 * Did our `bash` actually win?
 *
 * Verified in pi source: extension tools DO replace built-ins, but among *extensions* the
 * first registration of a name wins, so another loaded extension that also registers `bash`
 * can beat us silently. That failure mode is invisible — refs would then reach the child as
 * literal `{{sec:…}}` text with no error from pi at all — so it is detected explicitly and
 * session_start turns a false result into a loud notify().
 *
 * `source !== "builtin"` alone is NOT enough: a rival extension's tool carries
 * `source: "extension"` (or `"cli"`, or a scope name) too, which is why identity is decided
 * by comparing paths rather than by reading a source label.
 */
export function bashIsOwnedByPiSecret(pi: ExtensionAPI): boolean {
  const effective = pi.getAllTools().find((t) => t.name === "bash");
  // No bash at all, or still the builtin: we did not register, or registration did not take.
  if (!effective || effective.sourceInfo.source === "builtin") return false;
  const path = effective.sourceInfo.path;
  if (typeof path !== "string" || path.length === 0) return false;
  return resolveRealPath(path) === OUR_ENTRY;
}

export function registerSecureBash(pi: ExtensionAPI, cwd: string, options: SecureBashOptions): void {
  // createBashToolDefinition already carries promptSnippet, promptGuidelines,
  // renderCall and renderResult, so registering it preserves built-in presentation.
  pi.registerTool(createSecureBashToolDefinition(cwd, options) as unknown as ToolDefinition);
}
