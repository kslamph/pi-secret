import { createBashToolDefinition, type ExtensionAPI, type ToolDefinition } from "@earendil-works/pi-coding-agent";
import type { Vault } from "../vault.ts";
import { injectBashCommand } from "../glue.ts";
import { scrubText } from "../scrub.ts";

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
 * Did our `bash` actually win?
 *
 * Among *extensions* the first registration of a name wins, so another loaded
 * extension that also registers `bash` can beat us silently. That failure mode is
 * invisible — refs would reach the child as literal `{{sec:…}}` text and pi would
 * report no error at all — so it is detected explicitly and Task 10 turns a false
 * result into a loud notify(). `source !== "builtin"` alone is NOT enough: a rival
 * extension's tool carries `source: "extension"` too. Our registration is
 * identified by its path, which contains the package name "pi-secure" for any
 * install layout of this package. Fail-safe: a false negative can only produce a
 * loud notify, never a silent insecure success.
 */
export function bashIsOwnedByPiSecure(pi: ExtensionAPI): boolean {
  const effective = pi.getAllTools().find((t) => t.name === "bash");
  if (!effective || effective.sourceInfo.source === "builtin") return false;
  const { path, baseDir } = effective.sourceInfo;
  return /pi-secure/.test(path) || (baseDir !== undefined && /pi-secure/.test(baseDir));
}
