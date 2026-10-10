import { mkdtempSync, existsSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it, vi } from "vitest";
import { Vault } from "../src/vault.ts";
import {
  captureFromText,
  injectBashCommand,
  injectToolCall,
  isDocPath,
  scrubMessageText,
  scrubOutputSnapshot,
  scrubToolResult,
} from "../src/glue.ts";

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
    expect(out.blocked?.reason).toMatch(/would store the\s+placeholder text/);
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
    const dir = mkdtempSync(join(tmpdir(), "pi-secret-glue-"));
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
    const dir = mkdtempSync(join(tmpdir(), "pi-secret-glue-"));
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
    const details: Record<string, unknown> = { fullOutputPath: join(tmpdir(), "pi-secret-nope-xyz.txt") };
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
    expect(out.blocked?.reason).toMatch(/would store the\s+placeholder text|literal/);
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

/**
 * Review 2026-10-08, finding M1: `scrubToolResult` scrubs `details` with the same
 * generic string walk as content, so `details.fullOutputPath` — a PATH, not model-facing
 * text — was itself eligible for masking. When the path happened to match a shape
 * (a temp name containing `password=` or a token-shaped segment), the pointer handed to
 * `scrubOutputSnapshot` no longer existed, the rewrite failed, and the contract's
 * fail-closed branch DELETED the pointer — which is right for the model but means the
 * UNSCRUBBED snapshot file stays on disk forever with nothing pointing at it. A masked
 * pointer turns a leak into an invisible one.
 */
describe("the truncation snapshot pointer must survive scrubbing", () => {

  it("leaves fullOutputPath untouched while still masking its file contents", () => {
    const dir = mkdtempSync(join(tmpdir(), "pi-secret-path-"));
    // A temp path that a credential-shape matcher would happily rewrite.
    const file = join(dir, "password=ghp_A1b2C3d4E5f6G7h8I9j0K1L2M3N4O5P6Q7R8-out.txt");
    writeFileSync(file, `full output follows\n${GH}\n`);
    const vault = new Vault("t");
    vault.add("gh_pat", GH, "prompt");
    try {
      const details: Record<string, unknown> = { fullOutputPath: file, truncation: {} };
      const out = scrubToolResult({ toolName: "bash", content: [{ type: "text", text: "ok" }], details }, vault, { fileReads: false });
      expect((out.details as Record<string, unknown>).fullOutputPath).toBe(file);
      scrubOutputSnapshot(out.details, vault);
      expect(readFileSync(file, "utf8")).not.toContain(GH);
      expect(readFileSync(file, "utf8")).toContain("{{sec:gh_pat}}");
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

describe("isDocPath — where quoting the syntax is the norm (§12h)", () => {
  it("accepts docs/tests/fixtures/examples segments and template suffixes", () => {
    for (const p of [
      "README.md", "docs/design.md", "DOC.md", "test/x.ts", "tests/a.test.ts",
      "test/fixtures/realistic-bashrc.env", "examples/quickstart.md", "config.example",
      "deploy.sample", "ci.template",
    ]) {
      expect(isDocPath(p), p).toBe(true);
    }
  });

  it("rejects real config and source targets, including look-alike segments", () => {
    for (const p of [".env", "config.yml", "src/index.ts", "notes.txt", "mydocs/x.env"]) {
      expect(isDocPath(p), p).toBe(false);
    }
  });
});

describe("injectToolCall — write/edit ref gate (§12h)", () => {
  it("doc target: allows a non-resolving ref, notifies once, substitutes nothing", () => {
    const input = { path: "README.md", content: "use {{sec:name}} and {{sec:github_token}} here" };
    const out = injectToolCall("write", input, makeVault());
    expect(out.blocked).toBeUndefined();
    expect(out.expanded).toEqual([]);
    // Byte-identical: the allow path must return BEFORE expansion, or a doc quoting a
    // resolving name would become the one file on disk that holds the value.
    expect(input.content).toBe("use {{sec:name}} and {{sec:github_token}} here");
    expect(out.notify).toMatch(/README\.md/);
    expect(out.notify).toMatch(/names only/i);
  });

  it("doc target: a RESOLVING ref is allowed for documentation and not substituted", () => {
    const input = { path: "docs/setup.md", content: "run it with {{sec:gh_pat}}" };
    const out = injectToolCall("write", input, makeVault());
    expect(out.blocked).toBeUndefined();
    expect(out.expanded).toEqual([]);
    expect(input.content).toContain("{{sec:gh_pat}}");
    expect(out.notify).toMatch(/docs\/setup\.md/);
  });

  it("non-doc target, non-resolving ref: silent allow, content untouched", () => {
    const input = { path: "notes.txt", content: "the syntax is {{sec:name}}" };
    const out = injectToolCall("write", input, makeVault());
    expect(out.blocked).toBeUndefined();
    expect(out.notify).toBeUndefined();
    expect(input.content).toBe("the syntax is {{sec:name}}");
  });

  it("non-doc target, resolving ref: still refused, and the reason says why it resolves", () => {
    const out = injectToolCall("edit", { path: "config.yml", oldText: "a", newText: "k={{sec:gh_pat}}" }, makeVault());
    expect(out.blocked?.reason).toMatch(/would store the\s+placeholder text/);
    expect(out.blocked?.reason).toMatch(/resolves/);
    expect(out.blocked?.reason).not.toContain(GH);
  });


  it("the scrubber's reserved marker is never prose in a real target (canary: masked value persisted)", () => {
    const out = injectToolCall("write", { path: "leak.txt", content: "token={{sec:redacted}}" }, makeVault());
    expect(out.blocked?.reason).toMatch(/marker|redacted/);
    expect(out.blocked?.reason).not.toContain(GH);
  });

  it("a doc target may quote the reserved marker (the spec and README do)", () => {
    const input = { path: "docs/design.md", content: "the fallback renders {{sec:redacted}}" };
    const out = injectToolCall("write", input, makeVault());
    expect(out.blocked).toBeUndefined();
    expect(input.content).toContain("{{sec:redacted}}");
    expect(out.notify).toMatch(/docs\/design\.md/);
  });

  it("a heredoc carrying the reserved marker RUNS — the marker backs no value", () => {
    // Changed 2026-10-10. This used to be refused, on the reasoning that the marker
    // means "a masked value is being written somewhere". It does not: nothing resolves
    // from `sec:redacted`, so refusing protected nothing and blocked ordinary work —
    // including editing this project's own docs and tests, which are full of it. The
    // heredoc-into-a-file mistake is still reported by the user-only redirect warning.
    const out = injectBashCommand("cat <<'EOF'\n{{sec:redacted}}\nEOF", makeVault());
    expect(out.block).toBeUndefined();
    expect(out.command).toContain("{{sec:redacted}}");
  });

  it("a ref in the path field is refused whatever the target class", () => {
    const out = injectToolCall("write", { path: "docs/{{sec:name}}.md", content: "x" }, makeVault());
    expect(out.blocked?.reason).toMatch(/path/i);
  });
});

describe("injectBashCommand — prose refs in non-expanding contexts (§12h)", () => {
  it("the commit-message incident: quoted heredoc, non-resolving name, passes through", () => {
    // NB: the original incident quoted the RESERVED marker name; quoting THAT
    // through bash into a non-doc file stays refused (see the test below), so the
    // vector stands for the class — prose quoting a placeholder nobody stores.
    const cmd = "cat > /tmp/commit-msg.txt <<'MSG'\nfix: use {{sec:token}} here\nMSG";
    const out = injectBashCommand(cmd, makeVault());
    expect(out.block).toBeUndefined();
    expect(out.command).toBe(cmd);
    expect(out.env).toEqual({});
  });

  it("the same heredoc with a RESOLVING name is still refused", () => {
    const out = injectBashCommand("cat <<'EOF'\n{{sec:gh_pat}}\nEOF", makeVault());
    expect(out.block?.reason).toMatch(/will not expand it/);
  });
});
