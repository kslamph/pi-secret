import { describe, expect, it } from "vitest";
import { scrubText } from "../src/scrub.ts";
import { Vault } from "../src/vault.ts";

const GH = "ghp_A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8";

function vault() {
  const v = new Vault("t");
  v.add("gh_pat", GH, "prompt");
  return v;
}

// 2026-10-10, from a real session. get_search_content returned a vendor API page and pi-secret
// reported "masked 2 secret occurrence(s)". Both were documentation and code, not credentials:
// a Python SDK example reading api_key=<an env lookup> and a JavaScript one reading apiKey=<an
// env lookup>. isPlaceholderValue and hasSecretReferencePrefix give the right verdict on each
// - but they were only ever wired into the CAPTURE path, so the shape pass in scrub.ts went on
// masking documentation. Nothing was captured: the vault is not on this path at all, so this is
// NOT over-capture. It is over-masking, which is worse than cosmetic because it manufactures a
// redaction marker where the page had a placeholder, and the model is then told a credential was
// hidden.
describe("the scrub path applies the vetoes the capture path already had", () => {
  it("leaves an env lookup written as documentation untouched", () => {
    // NOTE: these inputs were once committed already-masked (`api_key={{sec:redacted}}"BAI…`),
    // the very bug under test applied to its own fixture. A line that already holds a ref is
    // skipped by the scrubber, so that version passed without exercising the vetoes at all.
    for (const line of [
      'client = OpenAI(    api_key=os.environ["BAI_API_KEY"],    base_url="https://api.b.ai/v1",)',
      'const client = new OpenAI({  apiKey: process.env.BAI_API_KEY,  baseURL: "https://api.b.ai/v1" });',
      "x-api-key: $BAI_API_KEY_VALUE",
    ]) {
      const out = scrubText(line, vault(), { shapes: true });
      expect(out.hits, line).toBe(0);
      expect(out.text, line).toBe(line); // byte-identical: the example still runs
    }
  });

  it("still masks a real credential, which is the point of the whole file", () => {
    for (const line of ["password=" + GH, "api_key=" + GH, "authorization: Bearer " + GH]) {
      expect(scrubText(line, vault(), { shapes: true }).hits, line).toBe(1);
    }
  });

  it("still masks a dotted value that is not an accessor", () => {
    // The prefix arm must not become a general dotted-token exemption: this is not process.env
    // or os.environ. Same bug class as the JWT case - the broad looksLikeSecretReference
    // predicate excused any dotted token, `token: eyJ...` included - pinned so the narrow one
    // stays narrow.
    expect(scrubText("password=hunter2.example", vault(), { shapes: true }).hits).toBe(1);
    expect(scrubText("AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE", vault(), { shapes: true }).hits).toBe(1);
  });

  it("leaves the placeholder-shaped values alone, same as capture does", () => {
    for (const line of ["api_key=<BAI_API_KEY>", "token=${GITHUB_TOKEN}", "password=%DB_PASSWORD%"]) {
      expect(scrubText(line, vault(), { shapes: true }).hits, line).toBe(0);
    }
  });
});
