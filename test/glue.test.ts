import { mkdtempSync, existsSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it, vi } from "vitest";
import { Vault } from "../src/vault.ts";
import { captureFromText, injectBashCommand, injectToolCall, scrubMessageText, scrubOutputSnapshot, scrubToolResult } from "../src/glue.ts";

const GH = "ghp_A1b2C3d4E5f6G7h8I9j0K1L2M3N4O5P6Q7R8";
const K = "4f9c1a7e2b8d0a3c5e7f1b3d9a2c4e6f8b0d2a4c";

function makeVault(): Vault {
  const v = new Vault("t");
  v.add("gh_pat", GH, "prompt");
  return v;
}

describe("injectBashCommand", () => {
  it("rewrites the command and returns env, never the value in text", () => {
    const v = makeVault();
    const out = injectBashCommand('curl -H "Authorization: Bearer {{sec:gh_pat}}" https://api.github.com', v);
    expect(out.command).not.toContain(GH);
    expect(out.command).toContain("__PISEC_GH_PAT");
    expect(out.expanded).toEqual(["gh_pat"]);
    expect(Object.values(out.env)).toEqual([GH]);
  });

  it("blocks an unknown ref with an actionable reason", () => {
    const out = injectBashCommand("echo {{sec:nope}}", makeVault());
    expect(out.block?.reason).toMatch(/sec:nope not found/);
    expect(out.block?.reason).toMatch(/Available: sec:gh_pat/);
    expect(out.command).toContain("{{sec:nope}}");
  });

  it("blocks an inert ref instead of sending a literal placeholder", () => {
    const out = injectBashCommand("cat <<'EOF'\n{{sec:gh_pat}}\nEOF", makeVault());
    expect(out.block?.reason).toMatch(/will not expand/);
  });

  it("leaves a ref-free command untouched", () => {
    const out = injectBashCommand("ls -la", makeVault());
    expect(out.command).toBe("ls -la");
    expect(out.env).toEqual({});
    expect(out.expanded).toEqual([]);
  });

  it("expands the same ref twice with one env var", () => {
    const out = injectBashCommand("echo {{sec:gh_pat}} {{sec:gh_pat}}", makeVault());
    expect(out.expanded).toEqual(["gh_pat"]);
    expect(Object.keys(out.env)).toHaveLength(1);
  });
});

describe("injectToolCall", () => {
  it("blocks refs in file-writing tools", () => {
    const out = injectToolCall("write", { path: ".env", content: `T={{sec:gh_pat}}` }, makeVault());
    expect(out.blocked?.reason).toMatch(/not written to files/);
    expect(out.expanded).toEqual([]);
  });

  it("blocks refs in read-only path tools", () => {
    expect(injectToolCall("read", { path: "{{sec:gh_pat}}" }, makeVault()).blocked?.reason).toMatch(
      /not a valid path/,
    );
  });

  it("expands refs in custom tool args, in place, value present", () => {
    const input: Record<string, unknown> = { headers: { authorization: "Bearer {{sec:gh_pat}}" }, n: 4 };
    const out = injectToolCall("http_request", input, makeVault());
    expect((input.headers as Record<string, string>).authorization).toBe(`Bearer ${GH}`);
    expect(out.expanded).toEqual(["gh_pat"]);
    expect(out.blocked).toBeUndefined();
  });

  it("leaves a clean payload alone", () => {
    const input: Record<string, unknown> = { url: "https://example.com" };
    expect(injectToolCall("http_request", input, makeVault()).expanded).toEqual([]);
  });

  it("does not mutate bash input — the spawnHook owns bash expansion", () => {
    const original = 'printf %s "{{sec:gh_pat}}"';
    const input: Record<string, unknown> = { command: original };
    const out = injectToolCall("bash", input, makeVault());
    expect(input.command).toBe(original);
    expect(out.expanded).toEqual([]);
  });

  it("expands refs inside array-valued params", () => {
    const input: Record<string, unknown> = { headers: ["X-A: {{sec:gh_pat}}", "plain"] };
    const out = injectToolCall("http_request", input, makeVault());
    expect((input.headers as string[])[0]).toBe(`X-A: ${GH}`);
    expect((input.headers as string[])[1]).toBe("plain");
    expect(out.expanded).toEqual(["gh_pat"]);
  });
});

describe("scrubToolResult", () => {
  it("masks a vault value back to its ref", () => {
    const out = scrubToolResult(
      { toolName: "bash", content: [{ type: "text", text: `--header 'Authorization: Bearer ${GH}'` }] },
      makeVault(),
      { fileReads: false },
    );
    expect((out.content[0] as { text: string }).text).toContain("{{sec:gh_pat}}");
    expect(JSON.stringify(out.content)).not.toContain(GH);
    expect(out.hits).toBe(1);
  });

  it("masks ambient credential shapes in tool output", () => {
    const out = scrubToolResult(
      { toolName: "bash", content: [{ type: "text", text: "AWS_ACCESS_KEY_ID=AKIAABCDEFGHIJKLMNOP" }] },
      makeVault(),
      { fileReads: false },
    );
    expect((out.content[0] as { text: string }).text).toBe("AWS_ACCESS_KEY_ID={{sec:redacted}}");
  });

  it("honors fileReads: skip shape masking for read results", () => {
    const out = scrubToolResult(
      { toolName: "read", content: [{ type: "text", text: "AWS_ACCESS_KEY_ID=AKIAABCDEFGHIJKLMNOP" }] },
      makeVault(),
      { fileReads: false },
    );
    expect(out.hits).toBe(0);
  });

  it("still masks vault values in read results", () => {
    const out = scrubToolResult(
      { toolName: "read", content: [{ type: "text", text: `token=${GH}` }] },
      makeVault(),
      { fileReads: false },
    );
    expect((out.content[0] as { text: string }).text).toBe("token={{sec:gh_pat}}");
  });

  it("scrubs details objects too", () => {
    const out = scrubToolResult(
      { toolName: "bash", content: [{ type: "text", text: "ok" }], details: { stderr: `leaked ${GH}` } },
      makeVault(),
      { fileReads: false },
    );
    expect(JSON.stringify(out.details)).not.toContain(GH);
  });

  it("survives a scrubber throwing by failing closed", () => {
    const hostile: Vault = {
      values: () => {
        throw new Error("boom");
      },
      findByValue: () => undefined,
      names: () => [],
    } as unknown as Vault;
    const out = scrubToolResult({ toolName: "bash", content: [{ type: "text", text: "abc" }] }, hostile, {
      fileReads: false,
    });
    // Spec §11: replace the block rather than let unverified text through.
    expect((out.content[0] as { text: string }).text).toBe("{{sec:redacted}}");
  });
});

describe("scrubMessageText", () => {
  it("masks vault values and shapes", () => {
    const out = scrubMessageText(`token=${GH} AKIAABCDEFGHIJKLMNOP`, makeVault(), { shapes: true });
    expect(out).toContain("{{sec:gh_pat}}");
    expect(out).not.toContain(GH);
    expect(out).not.toContain("AKIAABCDEFGHIJKLMNOP");
  });

  it("fails closed when the scrubber throws", () => {
    const hostile = {
      values: () => {
        throw new Error("boom");
      },
      findByValue: () => undefined,
      names: () => [],
    } as unknown as Vault;
    expect(scrubMessageText("hello", hostile, { shapes: true })).toBe("{{sec:redacted}}");
  });
});

describe("scrubOutputSnapshot", () => {
  it("rewrites the snapshot file scrubbed and keeps the pointer", () => {
    const dir = mkdtempSync(join(tmpdir(), "pi-secure-glue-"));
    const file = join(dir, "out.txt");
    writeFileSync(file, `token=${GH}\nAWS_ACCESS_KEY_ID=AKIAABCDEFGHIJKLMNOP\n`);
    const details: Record<string, unknown> = { fullOutputPath: file, truncation: {} };
    scrubOutputSnapshot(details, makeVault());
    const scrubbed = readFileSync(file, "utf8");
    expect(scrubbed).toContain("{{sec:gh_pat}}");
    expect(scrubbed).not.toContain(GH);
    expect(scrubbed).not.toContain("AKIAABCDEFGHIJKLMNOP");
    expect(details.fullOutputPath).toBe(file);
  });

  it("on ANY failure unlinks the snapshot and deletes the pointer", () => {
    const dir = mkdtempSync(join(tmpdir(), "pi-secure-glue-"));
    const file = join(dir, "out.txt");
    writeFileSync(file, `token=${GH}\n`);
    const hostile = {
      values: () => {
        throw new Error("boom");
      },
      findByValue: () => undefined,
      names: () => [],
    } as unknown as Vault;
    const details: Record<string, unknown> = { fullOutputPath: file };
    scrubOutputSnapshot(details, hostile);
    expect(existsSync(file)).toBe(false);
    expect("fullOutputPath" in details).toBe(false);
  });

  it("drops a pointer to a missing file", () => {
    const details: Record<string, unknown> = { fullOutputPath: join(tmpdir(), "pi-secure-nope-xyz.txt") };
    scrubOutputSnapshot(details, makeVault());
    expect("fullOutputPath" in details).toBe(false);
  });
});

describe("captureFromText", () => {
  it("moves the value into the vault and returns a ref-bearing text", () => {
    const v = makeVault();
    const out = captureFromText(`staging deploy uses ${GH.slice(0, 20)}xyz`, v);
    expect(out.text).toContain("{{sec:");
    expect(out.captured[0]?.length).toBeGreaterThan(8);
    expect(v.resolve(out.captured[0]!.name)).toContain("xyz");
  });

  it("captures nothing from a git SHA line", () => {
    const v = makeVault();
    expect(captureFromText(`revert ${K}`, v).captured).toEqual([]);
  });

  it("never vaults a skipped candidate", () => {
    const v = makeVault();
    const out = captureFromText(`revert ${K}`, v);
    expect(v.names()).toEqual(["gh_pat"]);
    expect(out.captured).toEqual([]);
  });
});

describe("injectBashCommand — the ref must never survive unexpanded", () => {
  // Defense in depth: `expandBash` is the authority on whether a ref got
  // substituted, and the guard is a lexical pre-pass that has to track it. This
  // asserts the property itself rather than either mechanism, so it survives
  // either side gaining a new case.
  it("never returns an unblocked command that still contains a ref", () => {
    const commands = [
      "echo {{sec:gh_pat}}",
      "echo {{sec:spaced}}",
      "printf '<%s>' 'Bearer {{sec:gh_pat}}'",
      'curl -H "Authorization: Bearer {{sec:gh_pat}}" https://api.github.com',
      "cat <<EOF\ntoken={{sec:gh_pat}}\nEOF",
      "cat <<'EOF'\ntoken={{sec:gh_pat}}\nEOF",
      "echo {{sec:nope}}",
      "echo 'x\nrun {{sec:gh_pat}}",
      "echo {{sec:gh_pat}} && echo 'x'",
      "cat <<A <<'B'\nX {{sec:gh_pat}}\nA\nY {{sec:gh_pat}}\nB\n",
    ];
    for (const command of commands) {
      const out = injectBashCommand(command, makeVault());
      if (!out.block) {
        expect(out.command, `unblocked: ${command}`).not.toMatch(/\{\{sec:/);
      }
    }
  });

  it("blocks rather than spawning when a ref could not be substituted", () => {
    const out = injectBashCommand("cat <<'EOF'\n{{sec:gh_pat}}\nEOF", makeVault());
    expect(out.block).toBeDefined();
    expect(out.command).toContain("{{sec:gh_pat}}");
    expect(out.env).toEqual({});
  });
});

describe("captureFromText — never claim a capture the vault refused", () => {
  it("returns the ORIGINAL text when Vault.add throws, leaving no dangling ref", () => {
    const v = new Vault("t");
    vi.spyOn(v, "add").mockImplementation(() => {
      throw new Error("collides with existing shell variable");
    });
    const text = `deploy with ${GH}`;
    const out = captureFromText(text, v);
    // A ref left in the message would point at a secret that was never stored.
    expect(out.captured).toEqual([]);
    expect(out.text).toBe(text);
  });
});

describe("injectToolCall — vaulted LITERALS in tool arguments", () => {
  // The model should never hold a value, so a literal means something leaked
  // upstream (most likely a `read` of a credential file with shape masking off).
  // Refusing is the honest response; silently accepting helps the leak travel.
  it("blocks a write carrying the literal value, not just a ref", () => {
    const out = injectToolCall("write", { path: ".env", content: `TOKEN=${GH}` }, makeVault());
    expect(out.blocked?.reason).toMatch(/not written to files|literal/);
    expect(out.blocked?.reason).not.toContain(GH);
  });

  it("blocks a bash command carrying the literal value", () => {
    const out = injectToolCall("bash", { command: `printf %s "${GH}"` }, makeVault());
    expect(out.blocked).toBeDefined();
    expect(out.blocked?.reason).toContain("{{sec:gh_pat}}");
    expect(out.blocked?.reason).not.toContain(GH);
  });

  it("blocks a custom tool carrying the literal value", () => {
    const out = injectToolCall("http_request", { headers: { authorization: `Bearer ${GH}` } }, makeVault());
    expect(out.blocked).toBeDefined();
  });

  it("does not false-positive on a ref or an ordinary command", () => {
    expect(injectToolCall("bash", { command: 'printf %s "{{sec:gh_pat}}"' }, makeVault()).blocked).toBeUndefined();
    expect(injectToolCall("bash", { command: "ls -la" }, makeVault()).blocked).toBeUndefined();
  });

  it("ignores values below the scrub floor so short secrets cannot block everything", () => {
    const v = new Vault("t");
    v.add("short", "abc123", "prompt"); // 6 chars < MIN_SCRUBABLE_LENGTH
    expect(injectToolCall("bash", { command: "echo abc123" }, v).blocked).toBeUndefined();
  });
});
