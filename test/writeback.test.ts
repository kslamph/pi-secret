import { describe, expect, it } from "vitest";
import { mkdtempSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Vault } from "../src/vault.ts";
import { canonicalPath, injectToolCall, recordReadOrigins } from "../src/glue.ts";

// §12j: a ref may be expanded into write/edit content only for the file its value was READ
// from. Putting a value back where it was adds nothing to disk; anywhere else stays refused.

const SECRET = "wJalrXUtnFEMIK7MDENGbPxRfiCYqq8xzz9k";

function setup() {
  const cwd = mkdtempSync(join(tmpdir(), "writeback-"));
  writeFileSync(join(cwd, ".env"), `AWS_SECRET_ACCESS_KEY=${SECRET}\n`);
  const v = new Vault("t");
  v.add("aws_secret_access_key", SECRET, "output");
  recordReadOrigins(
    { toolName: "read", input: { path: ".env" }, content: [{ type: "text", text: `AWS_SECRET_ACCESS_KEY=${SECRET}\n` }] },
    v,
    cwd,
  );
  return { cwd, v };
}

describe("writing a ref back into the file it was read from", () => {
  it("expands the ref in an edit of the same file", () => {
    const { cwd, v } = setup();
    const input = {
      path: ".env",
      edits: [
        {
          oldText: "AWS_SECRET_ACCESS_KEY={{sec:aws_secret_access_key}}\n",
          newText: "AWS_SECRET_ACCESS_KEY={{sec:aws_secret_access_key}}\nAWS_REGION=eu-west-1\n",
        },
      ],
    };
    const out = injectToolCall("edit", input, v, { cwd });
    expect(out.blocked).toBeUndefined();
    expect(out.expanded).toEqual(["aws_secret_access_key"]);
    expect(input.edits[0]!.oldText).toBe(`AWS_SECRET_ACCESS_KEY=${SECRET}\n`);
    expect(input.edits[0]!.newText).toContain(`AWS_SECRET_ACCESS_KEY=${SECRET}\nAWS_REGION`);
    expect(input.path).toBe(".env");
    expect(out.notify).toContain("back into .env");
    expect(out.notify).not.toContain(SECRET);
  });

  it("expands in a full write of the same file, however the path is spelled", () => {
    const { cwd, v } = setup();
    for (const path of [join(cwd, ".env"), "./.env", "@.env", "sub/../.env"]) {
      const input = { path, content: "AWS_SECRET_ACCESS_KEY={{sec:aws_secret_access_key}}\n" };
      expect(injectToolCall("write", input, v, { cwd }).blocked, path).toBeUndefined();
      expect(input.content).toContain(SECRET);
    }
  });

  it("follows a symlink to the same file", () => {
    const { cwd, v } = setup();
    symlinkSync(join(cwd, ".env"), join(cwd, "link.env"));
    const input = { path: "link.env", content: "X={{sec:aws_secret_access_key}}" };
    expect(injectToolCall("write", input, v, { cwd }).blocked).toBeUndefined();
  });

  it("still refuses any OTHER file, and leaves the input untouched", () => {
    const { cwd, v } = setup();
    const input = { path: "config.ts", content: "const k = '{{sec:aws_secret_access_key}}';" };
    const out = injectToolCall("write", input, v, { cwd });
    expect(out.blocked?.reason).toContain("sec:aws_secret_access_key resolves");
    expect(input.content).toContain("{{sec:aws_secret_access_key}}");
  });

  it("refuses a mix, and says which ref could have gone back", () => {
    const { cwd, v } = setup();
    v.add("gh", "ghp_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8", "paste");
    const input = { path: ".env", content: "A={{sec:aws_secret_access_key}}\nB={{sec:gh}}\n" };
    const out = injectToolCall("write", input, v, { cwd });
    expect(out.blocked?.reason).toContain("sec:gh resolves");
    expect(out.blocked?.reason).toContain("(sec:aws_secret_access_key can)");
    expect(input.content).not.toContain(SECRET);
  });

  it("refuses without a cwd (no way to know the target)", () => {
    const { v } = setup();
    expect(injectToolCall("write", { path: ".env", content: "{{sec:aws_secret_access_key}}" }, v).blocked).toBeDefined();
  });

  it("does not record an origin for a file that only QUOTES the ref", () => {
    const { cwd, v } = setup();
    recordReadOrigins(
      { toolName: "read", input: { path: "notes.txt" }, content: [{ type: "text", text: "use {{sec:aws_secret_access_key}}" }] },
      v,
      cwd,
    );
    expect(v.hasOrigin("aws_secret_access_key", canonicalPath("notes.txt", cwd))).toBe(false);
  });

  it("records origins only for read, not for bash or grep output", () => {
    const { cwd, v } = setup();
    for (const toolName of ["bash", "grep"]) {
      recordReadOrigins({ toolName, input: { path: "other.env" }, content: [{ type: "text", text: SECRET }] }, v, cwd);
    }
    expect(v.hasOrigin("aws_secret_access_key", canonicalPath("other.env", cwd))).toBe(false);
  });

  it("writes a restorable ref into a doc-path file it came from instead of the literal name", () => {
    const cwd = mkdtempSync(join(tmpdir(), "writeback-"));
    const v = new Vault("t");
    v.add("token", SECRET, "output");
    recordReadOrigins({ toolName: "read", input: { path: "test/fixtures/.env" }, content: [{ type: "text", text: `token=${SECRET}` }] }, v, cwd);
    const input = { path: "test/fixtures/.env", content: "token={{sec:token}}" };
    expect(injectToolCall("write", input, v, { cwd }).blocked).toBeUndefined();
    expect(input.content).toBe(`token=${SECRET}`);
  });
});
