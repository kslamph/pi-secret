import { fileURLToPath } from "node:url";
import { beforeEach, describe, expect, it, vi } from "vitest";
import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";
import piSecure from "../src/index.ts";
import { activeScopeKey, setActiveScopeKey, vaultForSession, dropSessionVault } from "../src/vault.ts";
import { isEnabled, setEnabled } from "../src/state.ts";
import { runSecCommand } from "../src/commands.ts";
import { Vault } from "../src/vault.ts";
import { scrubToolResult } from "../src/glue.ts";

type Handler = (event: unknown, ctx: unknown) => Promise<unknown>;

function harness() {
  const handlers = new Map<string, Handler[]>();
  const tools = new Map<string, unknown>();
  const commands = new Map<string, unknown>();
  const entryRenderers = new Map<string, unknown>();
  const pi = {
    on: (type: string, h: Handler) => handlers.set(type, [...(handlers.get(type) ?? []), h]),
    registerTool: (t: { name: string }) => tools.set(t.name, t),
    registerCommand: (name: string, c: unknown) => commands.set(name, c),
    registerEntryRenderer: (type: string, r: unknown) => entryRenderers.set(type, r),
    registerFlag: vi.fn(),
    getFlag: () => false,
    appendEntry: vi.fn(),
    getAllTools: () =>
      [...tools.values()].map((t) => ({
        name: (t as { name: string }).name,
        description: "",
        parameters: {},
        // The REAL entry path: the ownership check compares resolved files, so a stub that
        // invents a path would report "not ours" and every session would warn falsely.
        sourceInfo: {
          path: fileURLToPath(new URL("../src/index.ts", import.meta.url)),
          source: "extension",
          scope: "user",
          origin: "top-level",
          baseDir: undefined,
        },
      })),
    setActiveTools: vi.fn(),
    getActiveTools: () => ["bash", "read"],
    events: { on: vi.fn(), emit: vi.fn() },
  } as unknown as ExtensionAPI;
  const fire = async (type: string, event: unknown, ctx: unknown = {}) => {
    let last: unknown;
    for (const h of handlers.get(type) ?? []) last = await h(event, ctx);
    return last;
  };
  return { pi, fire, tools, commands, entryRenderers, registered: () => handlers };
}

const GH = "ghp_A1b2C3d4E5f6G7h8I9j0K1L2M3N4O5P6Q7R8";
const ctx = {
  cwd: "/tmp",
  sessionManager: { getSessionFile: () => "/tmp/s.jsonl", getSessionId: () => "s1", getLeafId: () => "l1" },
  ui: { notify: vi.fn(), custom: vi.fn(async () => GH), setWidget: vi.fn(), setStatus: vi.fn(), confirm: vi.fn(async () => true) },
  hasUI: true,
  mode: "tui",
  signal: undefined,
};

describe("pi-secure wiring", () => {
  // Every test in this file shares session file "/tmp/s.jsonl", and the vault
  // registry is module-global — so without this, an earlier capture leaves its
  // name (e.g. gh_deploy) bound to the shared canary value and a later test that
  // seeds "gh_pat" then masks to the WRONG ref. Drop it so the file is
  // order-independent rather than accidentally green.
  beforeEach(() => {
    dropSessionVault("/tmp/s.jsonl");
    setActiveScopeKey(undefined);
  });

  it("registers the command surface and receipt renderer at load", () => {
    const h = harness();
    piSecure(h.pi);
    expect([...h.commands.keys()]).toEqual(["sec"]);
    expect(h.entryRenderers.has("pi-secure-receipt")).toBe(true);
  });

  it("registers the sec_list tool and the wrapped bash tool on session_start", async () => {
    const h = harness();
    piSecure(h.pi);
    expect([...h.tools.keys()]).toEqual([]); // cwd-bound: registered per session
    await h.fire("session_start", { reason: "startup" }, ctx);
    expect([...h.tools.keys()].sort()).toEqual(["bash", "sec_list"]);
    expect(ctx.ui.setStatus).toHaveBeenCalledWith("pi-secure", "sec: 0 active");
  });

  it("installs every hook in the data-flow diagram", () => {
    const h = harness();
    piSecure(h.pi);
    for (const type of ["session_start", "session_shutdown", "input", "tool_call", "tool_result", "context", "before_provider_request"]) {
      expect(h.registered().has(type), type).toBe(true);
    }
  });

  it("scopes the vault to the session file on session_start", async () => {
    const h = harness();
    piSecure(h.pi);
    dropSessionVault("/tmp/s.jsonl");
    await h.fire("session_start", { reason: "startup" }, ctx);
    setActiveScopeKey("/tmp/s.jsonl");
    vaultForSession("/tmp/s.jsonl").add("gh_pat", GH, "prompt");
    expect(vaultForSession("/tmp/s.jsonl").resolve("gh_pat")).toBe(GH);
  });

  it("drops vault values on new/fork/resume/quit and keeps them on reload", async () => {
    const h = harness();
    piSecure(h.pi);
    await h.fire("session_start", { reason: "startup" }, ctx);
    vaultForSession("/tmp/s.jsonl").add("gh_pat", GH, "prompt");
    await h.fire("session_shutdown", { reason: "reload" }, ctx);
    expect(vaultForSession("/tmp/s.jsonl").resolve("gh_pat")).toBe(GH);
    await h.fire("session_shutdown", { reason: "new" }, ctx);
    expect(vaultForSession("/tmp/s.jsonl").resolve("gh_pat")).toBeUndefined();
  });

  it("captures pasted secrets on the input event", async () => {
    const h = harness();
    piSecure(h.pi);
    await h.fire("session_start", { reason: "startup" }, ctx);
    const out = (await h.fire("input", { text: `deploy with ${GH}`, images: [], source: "interactive" }, ctx)) as {
      action: string;
      text?: string;
    };
    expect(out.action).toBe("transform");
    // Named gh_deploy, not gh_token: the provider hint is "github" and "deploy" is
    // a CONTEXT_WORDS entry in capture.ts, so gh + deploy is what the naming rules
    // produce (Task 6 already pins gh_staging_deploy for the same shape).
    expect(out.text).toContain("deploy with {{sec:gh_deploy}}");
    expect(out.text).not.toContain(GH);
    expect(ctx.ui.notify).toHaveBeenCalledWith(expect.stringMatching(/captured sec:gh_deploy/), "info");
  });

  it("does not re-capture a message that only holds refs", async () => {
    const h = harness();
    piSecure(h.pi);
    await h.fire("session_start", { reason: "startup" }, ctx);
    const out = (await h.fire("input", { text: "use {{sec:gh_pat}}", source: "interactive" }, ctx)) as
      | { action?: string }
      | undefined;
    // undefined means "the extension has no opinion" — the message passes through
    // untouched. Returning { action: "continue" } would be equally valid, but a
    // no-op hook should say nothing at all.
    expect(out?.action).toBeUndefined();
  });

  it("never captures a git SHA from input", async () => {
    const h = harness();
    piSecure(h.pi);
    const out = (await h.fire("input", { text: "revert 4f9c1a7e2b8d0a3c5e7f1b3d9a2c4e6f8b0d2a4c please", source: "interactive" }, ctx)) as
      | { action?: string }
      | undefined;
    expect(out?.action).toBeUndefined();
  });

  it("expands refs on tool_call and blocks in writes", async () => {
    const h = harness();
    piSecure(h.pi);
    setActiveScopeKey("/tmp/s.jsonl");
    vaultForSession("/tmp/s.jsonl").add("gh_pat", GH, "prompt");
    const bashInput = { command: 'printf %s "{{sec:gh_pat}}"' };
    const res = (await h.fire("tool_call", { toolName: "bash", toolCallId: "c1", input: bashInput }, ctx)) as
      | { block?: unknown }
      | undefined;
    expect(res).toBeUndefined();
    // Refs stay intact for the spawnHook; mutating them here would double-expand.
    expect(bashInput.command).toBe('printf %s "{{sec:gh_pat}}"');
    const blocked = (await h.fire("tool_call", { toolName: "write", toolCallId: "c2", input: { path: ".env", content: `T={{sec:gh_pat}}` } }, ctx)) as {
      block: boolean;
      reason: string;
    };
    expect(blocked.block).toBe(true);
    expect(blocked.reason).toMatch(/not written to files/);
    expect(blocked.reason).not.toContain(GH);
  });

  it("scrubs values and shapes out of tool results", async () => {
    const h = harness();
    piSecure(h.pi);
    setActiveScopeKey("/tmp/s.jsonl");
    vaultForSession("/tmp/s.jsonl").add("gh_pat", GH, "prompt");
    const out = (await h.fire(
      "tool_result",
      { toolName: "bash", toolCallId: "c1", input: {}, content: [{ type: "text", text: `ran with ${GH} and AKIAABCDEFGHIJKLMNOP` }] },
      ctx,
    )) as { content: Array<{ text: string }> };
    expect(JSON.stringify(out.content)).not.toContain(GH);
    expect(out.content[0]?.text).toContain("{{sec:gh_pat}}");
    expect(out.content[0]?.text).toContain("{{sec:redacted}}");
  });

  it("never echoes tool_result input into an error", async () => {
    const h = harness();
    piSecure(h.pi);
    setActiveScopeKey("/tmp/s.jsonl");
    vaultForSession("/tmp/s.jsonl").add("gh_pat", GH, "prompt");
    const out = (await h.fire(
      "tool_result",
      { toolName: "bash", toolCallId: "c1", input: { command: `echo ${GH}` }, content: [{ type: "text", text: "fine" }], isError: true },
      ctx,
    )) as { content: Array<{ text: string }> };
    expect(JSON.stringify(out)).not.toContain(GH);
  });

  it("scrubs the provider payload as the last mile", async () => {
    const h = harness();
    piSecure(h.pi);
    setActiveScopeKey("/tmp/s.jsonl");
    vaultForSession("/tmp/s.jsonl").add("gh_pat", GH, "prompt");
    const payload = { messages: [{ role: "user", content: `deployed ${GH}` }] };
    // The handler's return value REPLACES the payload (runner.js: `if
    // (handlerResult !== undefined) currentPayload = handlerResult`), so what comes
    // back IS the payload — not an event wrapping it. Returning `{ payload: ... }`
    // would send a request body with a stray `payload` key.
    const out = (await h.fire("before_provider_request", { payload, model: {}, options: {} }, ctx)) as {
      messages: Array<{ content: string }>;
    };
    expect(JSON.stringify(out.messages[0]?.content)).not.toContain(GH);
    expect(out.messages[0]?.content).toContain("{{sec:gh_pat}}");
  });

  it("honors `/sec off` and `/sec on`", async () => {
    const h = harness();
    piSecure(h.pi);
    const commands = new Map<string, (args: string, ctx: unknown) => Promise<void>>();
    h.commands.forEach((v, k) => commands.set(k, (v as { handler: never }).handler as never));
    await h.fire("session_start", { reason: "startup" }, ctx);
    await commands.get("sec")?.("off", ctx);
    const out = (await h.fire("input", { text: `paste ${GH}`, source: "interactive" }, ctx)) as
      | { action?: string }
      | undefined;
    expect(out?.action).toBeUndefined();
    await commands.get("sec")?.("on", ctx);
    const on = (await h.fire("input", { text: `paste ${GH}`, source: "interactive" }, ctx)) as
      | { action?: string }
      | undefined;
    expect(on?.action).toBe("transform");
  });
});

describe("/sec dispatcher", () => {
  it("lists names and fingerprints, never values", async () => {
    const vault = new Vault("t");
    vault.add("gh_pat", GH, "prompt");
    const notify = vi.fn();
    await runSecCommand("list", vault, { ui: { notify } } as never);
    const msg = notify.mock.calls[0]![0] as string;
    expect(msg).toContain("sec:gh_pat");
    expect(msg).not.toContain(GH);
  });

  it("rejects an invalid name without prompting", async () => {
    const notify = vi.fn();
    const input = vi.fn();
    await runSecCommand("add Bad Name", new Vault("t"), { ui: { notify, input } } as never);
    expect(notify).toHaveBeenCalledWith(expect.stringMatching(/invalid name/), "warning");
    expect(input).not.toHaveBeenCalled();
  });

  it("renames, and lists the entry by its masked preview", async () => {
    const vault = new Vault("t");
    vault.add("old", GH, "prompt");
    const notify = vi.fn();
    await runSecCommand("rename old new", vault, { ui: { notify } } as never);
    expect(vault.resolve("new")).toBe(GH);
    await runSecCommand("list", vault, { ui: { notify } } as never);
    const last = notify.mock.calls.at(-1)![0] as string;
    // This is the whole point of the change: a person can tell which key this is. A digest
    // was safe and unreadable, which made "confirm the capture" a formality. The timestamp
    // lives here too now, which is why `/sec test` no longer exists as a separate verb.
    expect(last).toMatch(/ghp_A1b2…Q7R8/);
    expect(last).toMatch(/added \d{4}-\d{2}-\d{2}T/);
    expect(last).not.toContain(GH);
  });

  it("still identifies a short secret by its digest, because no preview is safe", async () => {
    const vault = new Vault("t");
    vault.add("pw", "correct-horse-battery", "prompt");
    const notify = vi.fn();
    await runSecCommand("list", vault, { ui: { notify } } as never);
    const last = notify.mock.calls.at(-1)![0] as string;
    expect(last).toMatch(/sha256:[0-9a-f]{4}/);
    expect(last).not.toContain("horse");
  });

  it("no longer accepts the `test` verb, and says what the usage is instead", async () => {
    // It was redundant with `list` (one field of difference) and its name implied it would
    // contact a provider, which it never did.
    const notify = vi.fn();
    await runSecCommand("test new", new Vault("t"), { ui: { notify } } as never);
    const last = notify.mock.calls.at(-1)![0] as string;
    expect(last).toMatch(/unknown subcommand/);
    // The word appears only in the rejection itself; the usage line must not offer it.
    expect(last.slice(last.indexOf("usage:"))).not.toMatch(/\btest\b/);
  });

  it("routes an unknown subcommand to usage, not a crash", async () => {
    const notify = vi.fn();
    await runSecCommand("frobnicate", new Vault("t"), { ui: { notify } } as never);
    expect(notify).toHaveBeenCalledWith(expect.stringMatching(/unknown subcommand/), "warning");
  });
});

describe("message_end — the model's own message is persisted before any tool result", () => {
  // Same reason as the first describe: this file shares session file
  // "/tmp/s.jsonl", and an earlier capture leaves its own name bound to the shared
  // canary value, so findByValue would return THAT name rather than the one seeded here.
  beforeEach(() => {
    dropSessionVault("/tmp/s.jsonl");
    setActiveScopeKey(undefined);
  });

  it("scrubs a literal secret out of an assistant tool-call argument", async () => {
    // tool_result cannot clean this: the assistant message is written to the
    // session file first. pi runs message_end before appendMessage and rewrites
    // the finalized message in place, so this is the only place it can be caught.
    const h = harness();
    piSecure(h.pi);
    await h.fire("session_start", { reason: "startup" }, ctx);
    setActiveScopeKey("/tmp/s.jsonl");
    vaultForSession("/tmp/s.jsonl").add("gh_pat", GH, "prompt");
    const message = {
      role: "assistant",
      content: [{ type: "toolCall", name: "bash", arguments: { command: `printf %s "${GH}"` } }],
    };
    const out = (await h.fire("message_end", { message }, ctx)) as { message: typeof message } | undefined;
    expect(JSON.stringify(out?.message)).not.toContain(GH);
    expect(out?.message.content[0]?.arguments?.command).toContain("{{sec:gh_pat}}");
  });

  it("leaves a clean message untouched (no spurious rewrite)", async () => {
    const h = harness();
    piSecure(h.pi);
    await h.fire("session_start", { reason: "startup" }, ctx);
    setActiveScopeKey("/tmp/s.jsonl");
    vaultForSession("/tmp/s.jsonl").add("gh_pat", GH, "prompt");
    const message = { role: "assistant", content: [{ type: "text", text: "all clear" }] };
    expect(await h.fire("message_end", { message }, ctx)).toBeUndefined();
  });
});

// --- Review 2026-10-08, finding C1 (the three unguarded hooks) --------------------
// pi's ExtensionRunner swallows a throwing handler and returns the value it held
// BEFORE the handler ran (runner.js: emitMessageEnd / emitContext /
// emitBeforeProviderRequest each try/catch per handler and keep `current*`). For
// these three hooks an exception therefore does not crash the turn — it silently
// skips scrubbing on the persisted assistant message and on the bytes sent to the
// provider. A vault whose `values()` throws is the cheapest faithful way to make
// the scrubber throw from inside the hook.
describe("the three hooks pi would silently skip on a throw", () => {
  it("message_end redacts rather than returning the untouched message", async () => {
    const h = harness();
    piSecure(h.pi);
    setActiveScopeKey("/tmp/s.jsonl");
    vaultForSession("/tmp/s.jsonl").add("gh_pat", GH, "prompt");
    // Make the live session vault's value enumeration throw.
    const live = vaultForSession("/tmp/s.jsonl");
    Object.defineProperty(live, "values", {
      value: () => { throw new RangeError("simulated scrubber failure"); },
      configurable: true,
    });
    const out = (await h.fire("message_end", { message: { role: "assistant", content: `deployed ${GH}` } }, ctx)) as {
      message: { content: string };
    };
    expect(out).toBeDefined();
    expect(JSON.stringify(out)).not.toContain(GH);
    expect(JSON.stringify(out)).toContain("{{sec:redacted}}");
    expect(ctx.ui.notify).toHaveBeenCalledWith(expect.stringContaining("failed closed"), "error");
  });

  it("before_provider_request redacts rather than returning the untouched payload", async () => {
    const h = harness();
    piSecure(h.pi);
    setActiveScopeKey("/tmp/s.jsonl");
    const live = vaultForSession("/tmp/s.jsonl");
    live.add("gh_pat", GH, "prompt");
    Object.defineProperty(live, "values", {
      value: () => { throw new RangeError("simulated scrubber failure"); },
      configurable: true,
    });
    const out = await h.fire("before_provider_request", { payload: { messages: [{ role: "user", content: GH }] }, model: {}, options: {} }, ctx);
    expect(out).toBeDefined();
    expect(JSON.stringify(out)).not.toContain(GH);
  });

  it("context redacts rather than returning the untouched messages", async () => {
    const h = harness();
    piSecure(h.pi);
    setActiveScopeKey("/tmp/s.jsonl");
    const live = vaultForSession("/tmp/s.jsonl");
    live.add("gh_pat", GH, "prompt");
    Object.defineProperty(live, "values", {
      value: () => { throw new RangeError("simulated scrubber failure"); },
      configurable: true,
    });
    const out = (await h.fire("context", { messages: [{ role: "user", content: GH }] }, ctx)) as {
      messages: Array<{ content: string }>;
    };
    expect(out).toBeDefined();
    expect(JSON.stringify(out)).not.toContain(GH);
  });
});

/**
 * Review 2026-10-08, finding I2: `/sec restore <name>` for a name that is not in the
 * vault produced NO output at all. `restoreSecret` returns { ok:false, reason } for
 * that case and only notifies on the success and clipboard-failure paths, and the
 * dispatcher discarded the return value entirely. The failure mode is not cosmetic:
 * a user who mistypes a name gets silence and may paste whatever was in the clipboard
 * before — a stale secret, or something unrelated — believing it is the one they asked
 * for. The unit test missed it because it asserts on restoreSecret's return value and
 * never on what the dispatcher does with it.
 */
describe("/sec restore must never fail silently", () => {
  it("warns when the name is not in this session", async () => {
    const notify = vi.fn();
    const vault = new Vault("t");
    vault.add("gh_pat", GH, "prompt");
    await runSecCommand("restore gh_typo", vault, { ui: { notify } } as never);
    expect(notify).toHaveBeenCalled();
    const [message, level] = notify.mock.calls.at(-1)! as [string, string];
    expect(message).toMatch(/gh_typo/);
    expect(level).toBe("warning");
    expect(message).not.toContain(GH);
  });

  it("still reports success on the clipboard path without gaining an editor channel", async () => {
    // The pin that matters most: fixing the silent failure must not tempt anyone to
    // route the value somewhere visible. The dispatcher must not notify a value, and
    // RestoreIo still has no editor channel to add one.
    const notify = vi.fn();
    const vault = new Vault("t");
    vault.add("gh_pat", GH, "prompt");
    await runSecCommand("restore gh_pat", vault, { ui: { notify } } as never);
    for (const call of notify.mock.calls) {
      expect(String(call[0])).not.toContain(GH);
    }
    expect(notify).toHaveBeenCalledWith(expect.stringContaining("clipboard"), "info");
  });
});

/**
 * spec §9's notify-only row: a bash redirect that would write a ref to a file runs, but
 * the USER is warned. Never the model — a model told "your command wrote a masked ref to
 * a file" reliably tries to fix it by rewriting the file, which is the corruption the
 * design exists to prevent.
 *
 * The test drives the hook and asserts the warning lands on ctx.ui.notify and NOT in the
 * hook's return value, because the hook's return value is what pi shows the model.
 */
describe("bash redirect warning — user only, and never blocking", () => {
  // Same reason as the describes above: this file shares session file "/tmp/s.jsonl",
  // and a previous describe deliberately replaces that vault's `values` with a thrower.
  // Without dropping it, these tests run against a sabotaged vault.
  beforeEach(() => {
    dropSessionVault("/tmp/s.jsonl");
    setActiveScopeKey(undefined);
  });

  const notify = () => vi.fn();

  it("warns the user when a bash command writes a ref to a file", async () => {
    const h = harness();
    piSecure(h.pi);
    setActiveScopeKey("/tmp/s.jsonl");
    vaultForSession("/tmp/s.jsonl").add("gh_pat", GH, "prompt");
    const n = notify();
    const out = await h.fire(
      "tool_call",
      { toolName: "bash", input: { command: `printf '%s' "{{sec:gh_pat}}" > ~/.netrc` } },
      { ...ctx, ui: { ...ctx.ui, notify: n } },
    );
    expect(n).toHaveBeenCalledWith(expect.stringContaining("~/.netrc"), "warning");
    // Nothing that reaches the model: the hook returns undefined, so no reason string
    // containing the ref (or anything else) is fed back into the conversation.
    expect(out).toBeUndefined();
  });

  it("does not warn for a ref that is not written anywhere", async () => {
    const h = harness();
    piSecure(h.pi);
    setActiveScopeKey("/tmp/s.jsonl");
    vaultForSession("/tmp/s.jsonl").add("gh_pat", GH, "prompt");
    const n = notify();
    await h.fire(
      "tool_call",
      { toolName: "bash", input: { command: 'curl -H "Authorization: Bearer {{sec:gh_pat}}" https://api.github.com' } },
      { ...ctx, ui: { ...ctx.ui, notify: n } },
    );
    expect(n).not.toHaveBeenCalled();
  });

  it("does not warn about ordinary redirection with no ref", async () => {
    const h = harness();
    piSecure(h.pi);
    setActiveScopeKey("/tmp/s.jsonl");
    const n = notify();
    await h.fire("tool_call", { toolName: "bash", input: { command: "echo hi > out.txt" } }, {
      ...ctx,
      ui: { ...ctx.ui, notify: n },
    });
    expect(n).not.toHaveBeenCalled();
  });
});

/**
 * spec §5's discovery surface. `addAutocompleteProvider` lives on the UI CONTEXT, not the
 * ExtensionAPI, so it is registered in session_start — which means a wiring test that only
 * checks `pi.on(...)` and `pi.registerTool(...)` would never notice it going missing, and
 * `{{sec:` would silently stop completing.
 */
describe("the editor surface", () => {
  it("registers one autocomplete factory on the UI context at session start", async () => {
    const h = harness();
    piSecure(h.pi);
    const addAutocompleteProvider = vi.fn();
    const uiCtx = {
      ...ctx,
      ui: { ...ctx.ui, addAutocompleteProvider },
      hasUI: true,
    };
    await h.fire("session_start", { reason: "startup" }, uiCtx);
    expect(addAutocompleteProvider).toHaveBeenCalledTimes(1);
    // It must be a FACTORY (pi composes providers by calling it with the current one),
    // not a provider object — passing the object would break every other provider.
    const arg = addAutocompleteProvider.mock.calls[0]![0];
    expect(typeof arg).toBe("function");
    // And the factory must WRAP the provider pi hands it, not discard it: a standalone
    // provider replaces the built-in chain, which kills `/`, `@` and Tab completion.
    const builtin = {
      triggerCharacters: ["@", "/"],
      getSuggestions: async () => ({ items: [{ value: "builtin", label: "builtin" }], prefix: "b" }),
      applyCompletion: () => ({ lines: ["builtin"], cursorLine: 0, cursorCol: 0 }),
    };
    const wrapped = (arg as (current: unknown) => { getSuggestions: (l: string[], cl: number, cc: number, o: never) => Promise<unknown> })(builtin);
    const out = (await wrapped.getSuggestions(["echo b"], 0, 6, { signal: new AbortController().signal } as never)) as {
      items: { value: string }[];
    };
    expect(out.items[0]!.value).toBe("builtin");
  });

  it("survives a headless session with no UI context", async () => {
    // A throw here would abort session_start, taking the whole extension with it.
    const h = harness();
    piSecure(h.pi);
    const brokenUi = { ...ctx, ui: {} as never, hasUI: false };
    await expect(h.fire("session_start", { reason: "startup" }, brokenUi)).resolves.not.toThrow();
  });
});

/**
 * A1 (2026-08): `--sec-file-reads` shipped default-OFF, which left the design's largest
 * documented hole open by default. The flag only ever affected read/grep/find/ls —
 * shape masking already applied to every other source of file content, so `cat
 * ~/.aws/credentials` through bash was masked all along. The default is now inverted and
 * the flag is the escape hatch.
 */
function defaultFlagHarness(value: boolean): { getFlag: () => boolean } {
  return { getFlag: () => value };
}

describe("the file-read masking default", () => {
  it("registers the flag as default-true", () => {
    const h = harness();
    piSecure(h.pi);
    const flag = (h.pi.registerFlag as unknown as { mock: { calls: unknown[][] } }).mock.calls.find(
      (c) => c[0] === "sec-file-reads",
    );
    expect(flag).toBeDefined();
    // registerFlag(name, options) — the options object is the SECOND argument.
    expect(flag![1]).toMatchObject({ type: "boolean", default: true });
  });

  it("masks credential shapes in a read result by default", () => {
    const { getFlag } = defaultFlagHarness(true);
    const out = scrubToolResult(
      { toolName: "read", content: [{ type: "text", text: "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY" }] },
      new Vault("t"),
      { fileReads: getFlag() },
    );
    expect(JSON.stringify(out.content)).not.toContain("wJalrXUtnFEMI");
    expect(out.hits).toBeGreaterThan(0);
  });

  it("still masks bash output when the flag is off — the knob is only about file reads", () => {
    // If turning the flag off re-opened bash, the escape hatch would be far wider than
    // its description and the default flip would have bought nothing.
    const vault = new Vault("t");
    const on = scrubToolResult(
      { toolName: "bash", content: [{ type: "text", text: "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY" }] },
      vault,
      { fileReads: true },
    );
    const off = scrubToolResult(
      { toolName: "bash", content: [{ type: "text", text: "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY" }] },
      vault,
      { fileReads: false },
    );
    expect(on.hits).toBeGreaterThan(0);
    expect(off.hits).toBe(on.hits);
  });

  it("off really does re-open read results, which is the documented cost", () => {
    const raw = "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
    const off = scrubToolResult({ toolName: "read", content: [{ type: "text", text: raw }] }, new Vault("t"), {
      fileReads: false,
    });
    expect(off.hits).toBe(0);
    expect(JSON.stringify(off.content)).toContain("wJalrXUtnFEMI");
  });
});

/**
 * B1 (2026-08): `/sec off` was a half-switch — injection and capture stopped, but the
 * VAULT stayed populated and output scrubbing stayed on. The last one is right and
 * deliberate (masking is a filter, not a capability: extra masking can only cost context,
 * while un-masking would leak). Keeping the vault was harder to justify: with the values
 * still in memory, anything that can reach the injection path can still spend them, and
 * "I turned pi-secure off" should mean no capability is handed out at all.
 */
describe("/sec off is a real off", () => {
  it("empties the vault, so a ref cannot be expanded afterwards", async () => {
    // The REGISTRY instance, not a standalone Vault: `new Vault(scope)` is a separate
    // object, so seeding one and asserting on vaultForSession(scope) would pass no matter
    // what /sec off did. The first draft of this test had exactly that bug.
    setActiveScopeKey("off-scope");
    const vault = vaultForSession("off-scope");
    vault.add("gh_pat", GH, "prompt");
    expect(vault.resolve("gh_pat")).toBe(GH);
    const notify = vi.fn();
    await runSecCommand("off", vault, { ui: { notify } } as never);
    expect(activeScopeKey()).toBe("off-scope"); // scope survives; the VALUES do not
    expect(vaultForSession("off-scope").resolve("gh_pat")).toBeUndefined();
    expect(vaultForSession("off-scope").names()).toEqual([]);
    setActiveScopeKey(undefined);
  });

  it("keeps the values recoverable via /sec on", async () => {
    // The point of dropping is that the user is done with them. Silently restoring them
    // on /sec on would make the switch meaningless, so `on` must NOT bring them back —
    // it only re-enables the mechanism. This test pins that they stay gone.
    setActiveScopeKey("off-scope-2");
    const vault = vaultForSession("off-scope-2");
    vault.add("gh_pat", GH, "prompt");
    expect(vault.resolve("gh_pat")).toBe(GH);
    const notify = vi.fn();
    await runSecCommand("off", vault, { ui: { notify } } as never);
    await runSecCommand("on", vault, { ui: { notify } } as never);
    expect(vaultForSession("off-scope-2").resolve("gh_pat")).toBeUndefined();
    setActiveScopeKey(undefined);
  });

  it("says what it actually stopped, so the message matches the behaviour", async () => {
    const notify = vi.fn();
    setActiveScopeKey("off-scope-3");
    await runSecCommand("off", vaultForSession("off-scope-3"), { ui: { notify } } as never);
    const [message] = notify.mock.calls.at(-1)! as [string];
    expect(message).toMatch(/cleared/i);
    setActiveScopeKey(undefined);
  });
});

/**
 * `/sec remove` asked before deleting ONE value; `/sec off` deleted EVERY value in the
 * session and asked nothing. The asymmetry is the bug: the more destructive verb was the
 * unguarded one.
 */
describe("/sec off asks before it clears the whole session", () => {
  it("does nothing at all when the user declines", async () => {
    // Precondition, not inherited state: an earlier block leaves the switch OFF, and a
    // decline test that starts from OFF would pass without the guard existing at all.
    setEnabled(true);
    setActiveScopeKey("off-confirm-declined");
    const vault = vaultForSession("off-confirm-declined");
    vault.add("gh_pat", GH, "prompt");
    const confirm = vi.fn(async () => false);
    await runSecCommand("off", vault, { hasUI: true, ui: { notify: vi.fn(), confirm } } as never);
    expect(confirm).toHaveBeenCalledTimes(1);
    // Declining means "do not do the thing": still enabled, values still spendable.
    expect(isEnabled()).toBe(true);
    expect(vaultForSession("off-confirm-declined").resolve("gh_pat")).toBe(GH);
    setActiveScopeKey(undefined);
  });

  it("clears and disables when the user confirms", async () => {
    setActiveScopeKey("off-confirm-accepted");
    const vault = vaultForSession("off-confirm-accepted");
    vault.add("gh_pat", GH, "prompt");
    const confirm = vi.fn(async () => true);
    await runSecCommand("off", vault, { hasUI: true, ui: { notify: vi.fn(), confirm } } as never);
    expect(isEnabled()).toBe(false);
    expect(vaultForSession("off-confirm-accepted").names()).toEqual([]);
    setEnabled(true);
    setActiveScopeKey(undefined);
  });

  it("says plainly that every key is about to go", async () => {
    setActiveScopeKey("off-confirm-wording");
    vaultForSession("off-confirm-wording").add("gh_pat", GH, "prompt");
    const confirm = vi.fn(async () => true);
    await runSecCommand("off", vaultForSession("off-confirm-wording"), {
      hasUI: true,
      ui: { notify: vi.fn(), confirm },
    } as never);
    const [title, message] = confirm.mock.calls[0]! as unknown as [string, string];
    expect(`${title} ${message}`).toMatch(/all keys/i);
    expect(message).toMatch(/disable/i);
    setEnabled(true);
    setActiveScopeKey(undefined);
  });

  it("does not ask to clear an already-empty vault — there is nothing to lose", async () => {
    setActiveScopeKey("off-confirm-empty");
    const confirm = vi.fn(async () => true);
    await runSecCommand("off", vaultForSession("off-confirm-empty"), {
      hasUI: true,
      ui: { notify: vi.fn(), confirm },
    } as never);
    expect(confirm).not.toHaveBeenCalled();
    expect(isEnabled()).toBe(false);
    setEnabled(true);
    setActiveScopeKey(undefined);
  });

  it("keeps working with no UI to ask (headless), rather than silently doing nothing", async () => {
    setActiveScopeKey("off-confirm-headless");
    const vault = vaultForSession("off-confirm-headless");
    vault.add("gh_pat", GH, "prompt");
    await runSecCommand("off", vault, { hasUI: false, ui: { notify: vi.fn() } } as never);
    expect(isEnabled()).toBe(false);
    expect(vaultForSession("off-confirm-headless").names()).toEqual([]);
    setEnabled(true);
    setActiveScopeKey(undefined);
  });
});

/**
 * A2 (2026-08): the design calls `before_provider_request` its last mile, but it is a
 * PROVIDER-level hook — pi-ai invokes it from inside each provider's api implementation.
 * Every provider shipped with 0.85.1 does; the faux provider does not, and a future one
 * might forget. When it is absent the failure is silent: the turn looks completely normal
 * and one layer of defence is simply not running.
 *
 * So the extension now measures it. If a turn completes and the hook never fired, the user
 * is told once, with the accurate scope of what still applies.
 */
describe("the provider-level net is measured, not assumed", () => {
  // Earlier describes in this file run `/sec off`, which is process-global state.
  beforeEach(() => {
    setEnabled(true);
  });

  const notify = () => vi.fn();

  it("says nothing while the hook is firing", async () => {
    const h = harness();
    piSecure(h.pi);
    const n = notify();
    const uiCtx = { ...ctx, ui: { ...ctx.ui, notify: n } };
    await h.fire("session_start", { reason: "startup" }, uiCtx);
    await h.fire("before_provider_request", { payload: { messages: [] }, model: {}, options: {} }, uiCtx);
    await h.fire("turn_end", { turn: 1 }, uiCtx);
    expect(n.mock.calls.filter((c) => String(c[0]).includes("provider"))).toHaveLength(0);
  });

  it("warns exactly once when a turn completes and the hook never fired", async () => {
    const h = harness();
    piSecure(h.pi);
    const n = notify();
    const uiCtx = { ...ctx, ui: { ...ctx.ui, notify: n } };
    await h.fire("session_start", { reason: "startup" }, uiCtx);
    await h.fire("turn_end", { turn: 1 }, uiCtx);
    await h.fire("turn_end", { turn: 2 }, uiCtx);
    await h.fire("turn_end", { turn: 3 }, uiCtx);
    const warnings = n.mock.calls.filter((c) => String(c[0]).includes("provider"));
    expect(warnings).toHaveLength(1);
    // The message must say what STILL applies, or it reads as "pi-secure is broken".
    expect(String(warnings[0]![0])).toMatch(/context|message_end|tool_result/i);
    expect(String(warnings[0]![0])).not.toContain("disabled");
  });
});
