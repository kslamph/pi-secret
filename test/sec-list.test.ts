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

  it("tells the model what a masked credential IS, and what to do instead", async () => {
    // Driven by a real session (2026-10-10): a grep of ~/.bashrc came back masked and the
    // model spent seven thinking blocks unable to tell a redaction from file content, then
    // hunted for the credential with od/xxd pipelines. Since 2026-10-11 shape matches come
    // back as usable refs, so the guideline must say: it is not file content, use the ref,
    // recovery is a leak, and only the marker needs /sec add.
    const joined = (createSecListTool(() => vaultWith()).promptGuidelines ?? []).join("\n");
    expect(joined).toMatch(/not file content/);
    expect(joined).toMatch(/Use the ref directly/);
    expect(joined).toMatch(/od, xxd, base64, sed/); // names the exact transforms it must not try
    expect(joined).toMatch(/leaks it/);
    expect(joined).toMatch(/Only \{\{sec:redacted\}\} is unusable/);
    expect(joined).toMatch(/\/sec add/);
    // Prevention: verify and consume without printing.
    expect(joined).toMatch(/Avoid commands that print credential values/);
    expect(joined).toMatch(/--password-stdin/);
    // Diagnosis must stay possible, restricted to the FACTS about a value.
    expect(joined).toMatch(/print only its properties/);
    expect(joined).toMatch(/length, prefix class, quoting, trailing whitespace/);
    expect(joined).toMatch(/never the value itself/);
  });

  it("marks entries adopted from tool output", async () => {
    const v = vaultWith();
    v.add("aws_secret_access_key", "wJalrXUtnFEMIK7MDENGbPxRfiCYzzzzzzzz", "output");
    const r = await createSecListTool(() => v).execute("t", {} as never, undefined, undefined, undefined as never);
    expect(JSON.stringify(r.content)).toContain("sec:aws_secret_access_key · len 36 · session-only · seen in tool output");
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

  it("carries no PART of a value either — this text reaches the provider", async () => {
    // Changed 2026-10-10. The tool used to print the truncated preview label
    // (`ghp_A1b2…Q7R8`), which is a slice of the real secret. Bounded or not, it is
    // characters of the value on the one surface whose purpose is to not send them.
    // The human-facing `/sec list` still shows the label: that goes to ui.notify and
    // never enters the transcript.
    const text = await textOf(createSecListTool(() => vaultWith()));
    for (const slice of [GH.slice(0, 4), GH.slice(0, 8), GH.slice(-4), GH.slice(-8)]) {
      expect(text).not.toContain(slice);
    }
    expect(text).not.toContain("\u2026"); // the preview's ellipsis
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
