import { describe, expect, it } from "vitest";
import { bashIsOwnedByPiSecure, createSecureBashToolDefinition } from "../src/tools/bash.ts";
import { Vault } from "../src/vault.ts";

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
