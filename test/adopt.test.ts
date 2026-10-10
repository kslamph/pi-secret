import { describe, expect, it } from "vitest";
import { Vault } from "../src/vault.ts";
import { MAX_ADOPTED, injectToolCall, scrubToolResult, vaultAdopter } from "../src/glue.ts";
import { scrubText } from "../src/scrub.ts";

// Credentials found in tool OUTPUT are stored for the session and shown as usable refs,
// instead of the unusable `{{sec:redacted}}`. The endpoint sees no plaintext either way;
// the difference is whether the model can keep working.

const SECRET = "wJalrXUtnFEMIK7MDENGbPxRfiCYqq8xzz9k";
const GH = "ghp_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8";

function scrub(text: string, v = new Vault("t")) {
  const adopted: string[] = [];
  const out = scrubText(text, v, { shapes: true, adopt: vaultAdopter(v, (n) => adopted.push(n)) });
  return { ...out, adopted, v };
}

describe("adopting credentials from tool output", () => {
  it("names a key=value credential after its key", () => {
    const r = scrub(`AWS_SECRET_ACCESS_KEY=${SECRET}`);
    expect(r.text).toBe("AWS_SECRET_ACCESS_KEY={{sec:aws_secret_access_key}}");
    expect(r.v.resolve("aws_secret_access_key")).toBe(SECRET);
    expect(r.v.get("aws_secret_access_key")?.source).toBe("output");
    expect(r.adopted).toEqual(["aws_secret_access_key"]);
  });

  it("names a provider-format token after its provider", () => {
    expect(scrub(`token is ${GH}`).text).toBe("token is {{sec:github}}");
  });

  it("names PEM and JWT matches by kind", () => {
    const pem = "-----BEGIN RSA PRIVATE KEY-----\nMIIEow\n-----END RSA PRIVATE KEY-----";
    expect(scrub(pem).text).toBe("{{sec:private_key}}");
    const jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U";
    expect(scrub(`Authorization: ${jwt}`).text).toContain("{{sec:");
    expect(scrub(`Authorization: ${jwt}`).text).not.toContain(jwt);
  });

  it("is idempotent by value: a repeat keeps its name and adds nothing", () => {
    const v = new Vault("t");
    scrub(`password=${SECRET}`, v);
    const again = scrub(`other_secret=${SECRET}`, v);
    expect(again.text).toBe("other_secret={{sec:password}}");
    expect(again.adopted).toEqual([]);
    expect(v.size()).toBe(1);
  });

  it("reuses a name the user already gave the value", () => {
    const v = new Vault("t");
    v.add("prod_db", SECRET, "prompt");
    expect(scrub(`password=${SECRET}`, v).text).toBe("password={{sec:prod_db}}");
    expect(v.size()).toBe(1);
  });

  it("masks a bare repeat of the adopted value where no shape fires, and its base64", () => {
    const b64 = Buffer.from(SECRET).toString("base64");
    const r = scrub(`api_key=${SECRET}\nusing ${SECRET} now\nencoded ${b64}`);
    expect(r.text).not.toContain(SECRET);
    expect(r.text).not.toContain(b64);
    expect(r.text.match(/\{\{sec:api_key\}\}/g)).toHaveLength(3);
  });

  it("gives a different value under a taken name a suffixed name", () => {
    const v = new Vault("t");
    v.add("password", "a-different-value-123", "prompt");
    expect(scrub(`password=${SECRET}`, v).text).toBe("password={{sec:password-2}}");
  });

  it("never mints an invalid or reserved name", () => {
    expect(scrub(`2fa_secret=${SECRET}`).text).toBe("2fa_secret={{sec:s_2fa_secret}}");
  });

  it("leaves placeholders and env lookups alone, as before", () => {
    expect(scrub("api_key=$API_KEY").text).toBe("api_key=$API_KEY");
    expect(scrub("password=<your-password>").text).toBe("password=<your-password>");
  });

  it("falls back to the marker past the cap, and still masks", () => {
    const v = new Vault("t");
    for (let i = 0; i < MAX_ADOPTED; i++) v.add(`k${i}`, `value-${i}-abcdefgh`, "output");
    const r = scrub(`password=${SECRET}`, v);
    expect(r.text).toBe("password={{sec:redacted}}");
    expect(v.size()).toBe(MAX_ADOPTED);
  });

  it("without an adopter, behaviour is unchanged: the generic marker", () => {
    expect(scrubText(`password=${SECRET}`, new Vault("t"), { shapes: true }).text).toBe("password={{sec:redacted}}");
  });

  it("scrubToolResult adopts across content and details with one name", () => {
    const v = new Vault("t");
    const out = scrubToolResult(
      { toolName: "bash", content: [{ type: "text", text: `token=${SECRET}` }], details: { raw: `token=${SECRET}` } },
      v,
      { fileReads: true, adopt: vaultAdopter(v) },
    );
    expect(JSON.stringify(out.content)).toContain("{{sec:token}}");
    expect(JSON.stringify(out.details)).toContain("{{sec:token}}");
    expect(v.size()).toBe(1);
  });
});

describe("the literal-value block and adopted entries", () => {
  it("does not refuse a literal the model knew independently of us", () => {
    // AWS's documented example key: adopted from a docs page, then legitimately written
    // into a test fixture by a model that knows it from training.
    const v = new Vault("t");
    v.add("aws_access_key_id", "AKIAIOSFODNN7EXAMPLE", "output");
    const out = injectToolCall("write", { path: "test/fixture.ts", content: 'const k = "AKIAIOSFODNN7EXAMPLE";' }, v);
    expect(out.blocked).toBeUndefined();
  });

  it("still refuses a literal of a value the user gave", () => {
    const v = new Vault("t");
    v.add("gh", GH, "paste");
    expect(injectToolCall("bash", { command: `echo ${GH}` }, v).blocked).toBeDefined();
  });
});
