import { describe, expect, it } from "vitest";
import { PI_SECRET_PROMPT, withPiSecretPrompt } from "../src/prompt.ts";
import { scrubText } from "../src/scrub.ts";
import { Vault } from "../src/vault.ts";
import { vaultAdopter } from "../src/glue.ts";

describe("the <pi_secret> system-prompt section", () => {
  it("survives pi-secret's own scrubber byte-identical, adopting nothing", () => {
    // It travels in every provider request, through context and before_provider_request.
    // If an example in it looked credential-shaped, the scrubber would rewrite our own
    // instructions on every turn and fill the vault with junk.
    const v = new Vault("t");
    v.add("api_key", "abcdefgh12345678", "paste");
    const out = scrubText(PI_SECRET_PROMPT, v, { shapes: true, adopt: vaultAdopter(v) });
    expect(out.text).toBe(PI_SECRET_PROMPT);
    expect(out.hits).toBe(0);
    expect(v.size()).toBe(1);
  });

  it("is appended once, however often it is applied", () => {
    const once = withPiSecretPrompt("base");
    expect(once.startsWith("base\n\n<pi_secret>")).toBe(true);
    expect(withPiSecretPrompt(once)).toBe(once);
  });

  it("covers the happy path, the limits, and the fix at each wall", () => {
    const p = PI_SECRET_PROMPT;
    // happy path
    expect(p).toMatch(/\{\{sec:NAME\}\}/);
    expect(p).toMatch(/sec_list/);
    expect(p).toMatch(/\/sec add NAME/);
    expect(p).toMatch(/Never ask them to paste/);
    // what output looks like, and what not to do about it
    expect(p).toMatch(/seen in tool output/);
    expect(p).toMatch(/not the file's real content/);
    expect(p).toMatch(/\{\{sec:redacted\}\} is the only ref with nothing behind it/);
    expect(p).toMatch(/od, xxd, base64, rev, cut, sed/);
    expect(p).toMatch(/Images and other binary output are not scrubbed/);
    // prevention
    expect(p).toMatch(/--password-stdin/);
    // files: the read-tool path AND its limit
    expect(p).toMatch(/open it with the read tool, not cat/);
    expect(p).toMatch(/Only the read tool lets pi-secret know which file/);
    expect(p).toMatch(/printf '%s\\n' "API_KEY=\{\{sec:NAME\}\}" >> \.env/);
    expect(p).toMatch(/Never put a credential into source code/);
    // shell traps
    expect(p).toMatch(/PISEC=\{\{sec:NAME\}\} sh -c/);
    expect(p).toMatch(/quoted heredoc/);
    // walls
    expect(p).toMatch(/When pi-secret refuses a call/);
    expect(p).toMatch(/Do not work around a refusal/);
  });
});
