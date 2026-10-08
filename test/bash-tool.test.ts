import { afterEach, describe, expect, it } from "vitest";
import { fileURLToPath } from "node:url";
import { bashIsOwnedByPiSecure, createSecureBashToolDefinition } from "../src/tools/bash.ts";
import { Vault } from "../src/vault.ts";
import { setEnabled } from "../src/state.ts";

const GH = "ghp_A1b2C3d4E5f6G7h8I9j0K1L2M3N4O5P6Q7R8";

/**
 * pi 0.85.1's resolveSpawnContext dereferences `ctx.sessionManager` whenever `ctx`
 * is truthy (exposeSessionEnvironment defaults true), so the plan's `{ cwd }`
 * context throws. Passing `undefined` is the minimal real-API context: the
 * definition's own cwd is used and no session env is exposed. The spawnHook still
 * runs, which is what these tests exercise.
 */
const EXEC_CTX = undefined as never;

describe("secure bash tool definition", () => {
  it("keeps the built-in name, prompt snippet and guidelines", () => {
    const def = createSecureBashToolDefinition(process.cwd(), { vault: () => new Vault("t") });
    expect(def.name).toBe("bash");
    // pi 0.85.1 snippet text; the plan's /Execute a bash command/ does not match
    // the installed builtin.
    expect(def.promptSnippet).toMatch(/Execute bash commands/);
    expect(def.promptGuidelines?.some((g) => g.includes("PI_"))).toBe(true);
    expect(typeof def.renderCall).toBe("function");
    expect(typeof def.renderResult).toBe("function");
  });

  it("routes the model's command through injectBashCommand", async () => {
    const vault = new Vault("t");
    vault.add("gh_pat", GH, "prompt");
    let seen: string | undefined;
    const def = createSecureBashToolDefinition(process.cwd(), {
      vault: () => vault,
      onExpand: (command, env) => {
        seen = command;
        expect(Object.values(env)).toEqual([GH]);
      },
    });
    const result = await def.execute(
      "call1",
      { command: 'printf "<%s>" "{{sec:gh_pat}}"' },
      undefined,
      undefined,
      EXEC_CTX,
    );
    const text = (result.content as Array<{ text: string }>).map((c) => c.text).join("");
    expect(text.trim()).toBe(`<${GH}>`); // the child saw the value...
    expect(seen).toContain("__PISEC_GH_PAT"); // ...the command text did not.
    expect(seen).not.toContain(GH);
  });

  it("reports whether our bash definition actually won registration", () => {
    const owned = [
      {
        name: "bash",
        sourceInfo: {
          source: "extension",
          path: "pi-secure",
          scope: "user",
          origin: "top-level",
          baseDir: undefined,
        },
      },
    ];
    const lost = [
      {
        name: "bash",
        sourceInfo: {
          source: "builtin",
          path: "<builtin:bash>",
          scope: "temporary",
          origin: "top-level",
          baseDir: undefined,
        },
      },
    ];
    const fakePi = (tools: unknown[]) => ({ getAllTools: () => tools }) as never;
    expect(bashIsOwnedByPiSecure(fakePi(owned))).toBe(true);
    expect(bashIsOwnedByPiSecure(fakePi(lost))).toBe(false);
    expect(bashIsOwnedByPiSecure(fakePi([]))).toBe(false);
  });

  it("reports not-owned when a rival extension won the bash race", () => {
    // R4-001: the old predicate returned true for ANY non-builtin source, so the
    // exact rival-extension silent-loss it documents was reported as owned.
    const rival = [
      {
        name: "bash",
        sourceInfo: {
          source: "extension",
          path: "sneaky-other-ext",
          scope: "user",
          origin: "top-level",
          baseDir: undefined,
        },
      },
    ];
    const fakePi = (tools: unknown[]) => ({ getAllTools: () => tools }) as never;
    expect(bashIsOwnedByPiSecure(fakePi(rival))).toBe(false);
  });

  it("throws instead of exec'ing an unresolvable ref", async () => {
    const def = createSecureBashToolDefinition(process.cwd(), { vault: () => new Vault("t") });
    await expect(
      def.execute("c2", { command: "echo {{sec:missing}}" }, undefined, undefined, EXEC_CTX),
    ).rejects.toThrow(/not found/);
  });

  it("leaves process.env untouched", async () => {
    const vault = new Vault("t");
    vault.add("gh_pat", GH, "prompt");
    const def = createSecureBashToolDefinition(process.cwd(), { vault: () => vault });
    await def.execute("c3", { command: "printf %s {{sec:gh_pat}}" }, undefined, undefined, EXEC_CTX);
    expect(Object.keys(process.env).filter((k) => k.startsWith("__PISEC_"))).toEqual([]);
  });

  it("scrubs the streamed partials handed to onUpdate", async () => {
    // tool_result never sees a streamed partial, so without wrapping onUpdate a
    // command that echoes a secret prints it live mid-turn. Assert on the payload
    // the renderer actually receives.
    const vault = new Vault("t");
    vault.add("gh_pat", GH, "prompt");
    const def = createSecureBashToolDefinition(process.cwd(), { vault: () => vault });
    const updates: string[] = [];
    await def.execute(
      "c4",
      { command: 'printf %s "{{sec:gh_pat}}"' },
      undefined,
      (partial) => {
        updates.push(JSON.stringify(partial));
      },
      EXEC_CTX,
    );
    expect(updates.length).toBeGreaterThan(0);
    const joined = updates.join("\n");
    expect(joined).toContain("{{sec:gh_pat}}");
    expect(joined).not.toContain(GH);
  });
});

/**
 * Review 2026-10-08, finding I1: `/sec off` told the user "refs will not expand",
 * and stopped expansion for every tool EXCEPT bash — bash is injected by the
 * spawnHook, which never consulted the enabled flag. So the single most
 * security-relevant injection path kept working after the user switched the whole
 * mechanism off, and the UI said otherwise.
 *
 * The fix must not merely stop substituting: a command containing a literal
 * `{{sec:NAME}}` would then run and report success, which is the false-confidence
 * class this project treats as its worst failure mode (`curl -H "Bearer
 * {{sec:gh}}"` would send a bogus header and look like it worked). So a ref while
 * disabled BLOCKS with a reason instead.
 */
describe("/sec off must actually stop bash ref injection", () => {
  afterEach(() => setEnabled(true));

  it("blocks a ref in bash while pi-secure is disabled", async () => {
    setEnabled(false);
    const vault = new Vault("t");
    vault.add("gh_pat", GH, "prompt");
    const def = createSecureBashToolDefinition(process.cwd(), { vault: () => vault });
    await expect(
      def.execute("d1", { command: 'printf %s "{{sec:gh_pat}}"' }, undefined, undefined, EXEC_CTX),
    ).rejects.toThrow(/disabled/i);
  });

  it("still runs ordinary commands while disabled", async () => {
    setEnabled(false);
    const vault = new Vault("t");
    vault.add("gh_pat", GH, "prompt");
    const def = createSecureBashToolDefinition(process.cwd(), { vault: () => vault });
    const result = await def.execute("d2", { command: "printf ok" }, undefined, undefined, EXEC_CTX);
    const text = (result.content as Array<{ text: string }>).map((c) => c.text).join("");
    expect(text).toContain("ok");
  });

  it("expands again after /sec on, for values added after the off", async () => {
    setEnabled(false);
    setEnabled(true);
    const vault = new Vault("t");
    vault.add("gh_pat", GH, "prompt");
    const def = createSecureBashToolDefinition(process.cwd(), { vault: () => vault });
    const result = await def.execute(
      "d3",
      { command: 'printf "<%s>" "{{sec:gh_pat}}"' },
      undefined,
      undefined,
      EXEC_CTX,
    );
    const text = (result.content as Array<{ text: string }>).map((c) => c.text).join("");
    expect(text.trim()).toBe(`<${GH}>`);
  });
});

/**
 * Review 2026-10-08: the ownership probe matched the substring "pi-secure" anywhere in
 * the extension's path, which cuts both ways. FALSE NEGATIVE: a legitimate install
 * under a path without that substring (a packaged cache, a monorepo checkout) reports
 * "not ours" and nags every session. FALSE POSITIVE — the dangerous direction, because
 * it suppresses the warning: anyone with a checkout at `…/pi-secure-fork/`, or any
 * extension deliberately named to contain the substring, silences the detector whose
 * entire job is "did another extension take `bash` from us".
 *
 * The fix is identity instead of a guess. pi stamps every extension's tools with the
 * extension's own sourceInfo, whose `baseDir` is the directory of the resolved entry
 * file (extensions/loader.js:444-449). This module can therefore compute its own
 * package directory from `import.meta.url` and compare — which is correct for a renamed
 * install (both sides move together) and correct for a fork (the two dirs differ, so
 * the warning fires when it should).
 */
describe("bash ownership is decided by real path identity, not a substring", () => {
  const tool = (sourceInfo: Record<string, unknown>) => ({
    name: "bash",
    sourceInfo: { source: "extension", scope: "user", origin: "top-level", ...sourceInfo },
  });
  const fakePi = (tools: unknown[]) => ({ getAllTools: () => tools }) as never;
  const ourDir = fileURLToPath(new URL("../src", import.meta.url)); // <pkg>/src

  it("accepts our own real package directory", () => {
    expect(bashIsOwnedByPiSecure(fakePi([tool({ path: `${ourDir}/index.ts`, baseDir: ourDir })]))).toBe(true);
  });

  it("rejects a rival checkout whose path merely CONTAINS pi-secure", () => {
    const fork = "/home/someone/experiments/pi-secure-fork/src";
    expect(bashIsOwnedByPiSecure(fakePi([tool({ path: `${fork}/index.ts`, baseDir: fork })]))).toBe(false);
  });

  it("accepts a renamed install, because our own path moved with it", () => {
    const renamed = "/opt/extension-cache/a1b2c3/src";
    // Simulates the same layout at a different location: pi reports that baseDir for
    // our extension, and this module's own URL is inside it, so they agree.
    expect(bashIsOwnedByPiSecure(fakePi([tool({ path: `${renamed}/index.ts`, baseDir: renamed })]))).toBe(
      renamed === ourDir,
    );
  });

  it("still reports not-ours for the builtin and for an empty registry", () => {
    expect(bashIsOwnedByPiSecure(fakePi([tool({ source: "builtin", path: "<builtin:bash>" })]))).toBe(false);
    expect(bashIsOwnedByPiSecure(fakePi([]))).toBe(false);
  });
});
