import { describe, expect, it } from "vitest";
import { createSecListTool } from "../src/tools/sec-list.ts";
import { Vault } from "../src/vault.ts";

const GH = "ghp_A1b2C3d4E5f6G7h8I9j0K1L2M3N4O5P6Q7R8";

function vaultWith(): Vault {
  const v = new Vault("t");
  v.add("gh_pat", GH, "prompt");
  return v;
}

async function textOf(def: ReturnType<typeof createSecListTool>): Promise<string> {
  const result = await def.execute("c1", {} as never, undefined, undefined, {} as never);
  return (result.content as Array<{ text: string }>).map((c) => c.text).join("\n");
}

describe("sec_list", () => {
  it("is named sec_list and advertises itself to the prompt", () => {
    const def = createSecListTool(() => vaultWith());
    expect(def.name).toBe("sec_list");
    expect(def.promptSnippet).toContain("{{sec:NAME}}");
  });

  it("teaches the one rule and forbids asking the user for a secret", async () => {
    const joined = (createSecListTool(() => vaultWith()).promptGuidelines ?? []).join("\n");
    // Guidelines are flattened into the system prompt, so each must name the tool
    // it refers to or the model has nothing to attach the advice to.
    expect(joined).toContain("sec_list");
    expect(joined).toContain("{{sec:");
    expect(joined).toMatch(/[Nn]ever ask the user/);
  });

  it("warns against the nested-shell expansion trap", async () => {
    const joined = (createSecListTool(() => vaultWith()).promptGuidelines ?? []).join("\n");
    // A value interpolated into a string a second shell parses becomes SOURCE.
    expect(joined).toMatch(/sh -c|eval/);
  });

  it("lists names and metadata, never values", async () => {
    const text = await textOf(createSecListTool(() => vaultWith()));
    expect(text).toContain("sec:gh_pat");
    expect(text).toContain("len 40");
    expect(text).not.toContain(GH);
  });

  it("returns value-free details", async () => {
    const def = createSecListTool(() => vaultWith());
    const result = await def.execute("c1", {} as never, undefined, undefined, {} as never);
    expect(JSON.stringify(result.details)).not.toContain(GH);
  });

  it("tells the model how to add one when the vault is empty", async () => {
    const text = await textOf(createSecListTool(() => new Vault("empty")));
    expect(text).toMatch(/\/sec add/);
  });
});
