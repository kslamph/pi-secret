import { describe, expect, it } from "vitest";
import { Vault } from "../src/vault.ts";
import { looksCredentialish, maskShapes, maskValues, scrubDeep, scrubText } from "../src/scrub.ts";

const GH = "ghp_A1b2C3d4E5f6G7h8I9j0K1L2M3N4O5P6Q7R8";
const DB = "postgres://admin:s3cr3t@db.internal:5432/app";
const SHORT = "abc";

const vault = new Vault("t");
vault.add("gh_pat", GH, "prompt");
vault.add("db_url", DB, "paste");

describe("maskValues", () => {
  it("replaces an exact value", () => {
    expect(maskValues(`token=${GH} ok`, [GH]).text).toBe(`token={{sec:redacted}} ok`);
  });

  it("replaces every occurrence", () => {
    expect(maskValues(`${GH} ${GH}`, [GH]).hits).toBe(2);
  });

  it("masks base64, base64url and hex forms of the value", () => {
    const b64 = Buffer.from(GH).toString("base64");
    const hex = Buffer.from(GH).toString("hex");
    expect(maskValues(b64, [GH]).text).toBe("{{sec:redacted}}");
    expect(maskValues(hex, [GH]).text).toBe("{{sec:redacted}}");
  });

  it("ignores values shorter than the scrub floor", () => {
    expect(maskValues("abc def", [SHORT]).hits).toBe(0);
  });

  it("masks the longer value first when one contains the other", () => {
    const inner = "AKIAABCDEFGHIJKLMNOP";
    const outer = `prefix${inner}suffix`;
    const out = maskValues(`${outer} ${inner}`, [outer, inner]);
    expect(out.text).toBe("{{sec:redacted}} {{sec:redacted}}");
    expect(out.text).not.toContain(inner);
  });

  it("leaves text without secrets untouched", () => {
    expect(maskValues("nothing here", [GH]).hits).toBe(0);
  });

  it("masks a line-wrapped base64 of a vaulted secret", () => {
    const b64 = Buffer.from(GH).toString("base64");
    const wrapped = b64.slice(0, 50) + "\n" + b64.slice(50);
    expect(wrapped).toContain("\n");
    const out = maskValues(wrapped, [GH]);
    expect(out.hits).toBe(1);
    expect(out.text).toBe("{{sec:redacted}}");
  });

  it("masks a space-separated base64 of a vaulted secret", () => {
    const b64 = Buffer.from(GH).toString("base64");
    const mid = Math.floor(b64.length / 2);
    const spaced = b64.slice(0, mid) + " " + b64.slice(mid);
    const out = maskValues(spaced, [GH]);
    expect(out.hits).toBe(1);
    expect(out.text).toBe("{{sec:redacted}}");
  });

  it("masks uppercase hex of a vaulted secret", () => {
    const hex = Buffer.from(GH).toString("hex").toUpperCase();
    const out = maskValues(hex, [GH]);
    expect(out.hits).toBe(1);
    expect(out.text).toBe("{{sec:redacted}}");
  });

  it("does not whitespace-tolerantly match a short raw value split by spaces", () => {
    // Req 12: an 8-char vault entry must NOT drag ordinary prose through the
    // whitespace-collapsed matcher — only derived encodings do that.
    expect(maskValues("I ran test 1234 twice", ["test1234"]).hits).toBe(0);
  });

  it("does not whitespace-tolerantly match a short raw value split by newlines", () => {
    const prose = "abc def\nghi jkl\nmno pqr";
    expect(maskValues(prose, ["abcdefghi"]).hits).toBe(0);
  });

  it("still masks wrapped base64 (Req 9 must not regress)", () => {
    const b64 = Buffer.from(GH).toString("base64");
    const wrapped = b64.slice(0, 50) + "\n" + b64.slice(50);
    const out = maskValues(wrapped, [GH]);
    expect(out.hits).toBe(1);
    expect(out.text).toBe("{{sec:redacted}}");
  });

  it("scrubs a ~1MB output with 16 entries in bounded time", () => {
    // Req 13 guard: the value pass must build its whitespace-stripped buffer ONCE
    // and index every form against it, not rebuild per form. Generous ceiling with
    // headroom below the 84348b4 baseline (~3129ms); timing is reported, not tight.
    const secrets = Array.from({ length: 16 }, (_, i) => "ghp_" + String(i).padStart(36, "0"));
    const line = "the quick brown fox jumps over the lazy dog\n";
    const big = line.repeat(24000); // ~1.08 MB
    expect(Buffer.byteLength(big, "utf8")).toBeGreaterThan(1_000_000);
    const start = Date.now();
    const out = maskValues(big, secrets);
    const ms = Date.now() - start;
    expect(out.hits).toBe(0); // secrets absent from the synthetic output
    expect(ms).toBeLessThan(1000); // 84348b4: ~3129ms; headroom target <1s
    // eslint-disable-next-line no-console
    console.log(`[perf] maskValues 1MB / 16 entries = ${ms}ms`);
  });
});

describe("maskShapes", () => {
  it("masks AWS access key ids", () => {
    expect(maskShapes("key AKIAABCDEFGHIJKLMNOP end").text).toBe("key {{sec:redacted}} end");
  });

  it("masks GitHub, Anthropic, Slack, OpenAI and Hugging Face tokens", () => {
    const samples = [
      GH,
      "sk-ant-api03-" + "a".repeat(80),
      "xoxb-EXAMPLE-NOT-A-REAL-SLACK-TOKEN",
      "sk-" + "A".repeat(35),
      "hf_" + "q".repeat(34),
      "glpat-" + "Z".repeat(20),
      "npm_" + "r".repeat(36),
      "dckr_pat_" + "w".repeat(27),
    ];
    for (const sample of samples) {
      expect(maskShapes(`value=${sample}`).text).toBe("value={{sec:redacted}}");
    }
  });

  it("masks PEM private key blocks", () => {
    const pem = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA\n-----END RSA PRIVATE KEY-----";
    expect(maskShapes(pem).text).toBe("{{sec:redacted}}");
  });

  it("masks JWTs", () => {
    const jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U";
    expect(maskShapes(`token: ${jwt}`).text).toBe("token: {{sec:redacted}}");
  });

  it("masks key=value credential shapes", () => {
    expect(maskShapes("aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY").text).toBe(
      "aws_secret_access_key = {{sec:redacted}}",
    );
    expect(maskShapes("PASSWORD: Tr0ub4dor&3xyzabc").text).toBe("PASSWORD: {{sec:redacted}}");
  });

  it("never leaves the tail of a credential unmasked", () => {
    // Regression: the value class once stopped at `&`, so everything after it was
    // leaked in the clear while the head looked masked.
    const line = "aws_secret_access_key=wJalrXUtnFEMI/K7MDENG&bPxRfiCYEXAMPLEKEY";
    const out = maskShapes(line);
    expect(out.text).toBe("aws_secret_access_key={{sec:redacted}}");
    expect(out.text).not.toContain("bPxRfiCYEXAMPLEKEY");
    expect(out.text).not.toContain("K7MDENG");
  });

  it("never masks a git SHA", () => {
    const sha = "4f9c1a7e2b8d0a3c5e7f1b3d9a2c4e6f8b0d2a4c";
    expect(maskShapes(`commit ${sha} (HEAD -> main)`).text).toBe(`commit ${sha} (HEAD -> main)`);
    expect(maskShapes(sha).hits).toBe(0);
  });

  it("never masks sha256 digests, uuids, semver or paths", () => {
    const hex64 = "a".repeat(64);
    const uuid = "123e4567-e89b-12d3-a456-426614174000";
    expect(maskShapes(hex64).hits).toBe(0);
    expect(maskShapes(uuid).hits).toBe(0);
    expect(maskShapes("version 1.2.3-beta.4").hits).toBe(0);
    expect(maskShapes("/home/kslam/piext/pi-secure/src/index.ts").hits).toBe(0);
  });

  it("leaves ordinary prose alone", () => {
    const prose =
      "The renderer calls structuredClone(toolCall.arguments) before the hook, so mutation is safe.";
    expect(maskShapes(prose).hits).toBe(0);
  });

  it("masks a value tail cut by a backslash", () => {
    // Regression: the KV value class excluded backslash, so the head was masked
    // and everything after the backslash leaked in the clear — the same partial-mask
    // failure the `&` tail test guards against, now on the backslash edge.
    const line = "aws_secret_access_key = wJalrXUtnFEMI/K7MDENG\\bPxRfiCYEXAMPLEKEY";
    const out = maskShapes(line);
    expect(out.text).toBe("aws_secret_access_key = {{sec:redacted}}");
    expect(out.text).not.toContain("bPxRfiCYEXAMPLEKEY");
    expect(out.text).not.toContain("K7MDENG");
  });

  it("stops a KV capture at a JSON-ish closing quote instead of running on", () => {
    // Guards the backslash edit: the value class must still exclude `"` so a quoted
    // value terminates at its closing quote rather than consuming the trailing JSON.
    const line = '{"api_key": "secretvalue", "noise": "y"}';
    const out = maskShapes(line);
    expect(out.text).toBe('{"api_key": "{{sec:redacted}}", "noise": "y"}');
    expect(out.text).not.toContain("secretvalue");
  });
});

describe("scrubText", () => {
  it("resolves a known secret back to its ref so the model can reuse it", () => {
    expect(scrubText(`Authorization: Bearer ${GH}`, vault).text).toBe(
      "Authorization: Bearer {{sec:gh_pat}}",
    );
  });

  it("uses the generic marker for shape hits", () => {
    expect(scrubText("AWS_ACCESS_KEY_ID=AKIAABCDEFGHIJKLMNOP", vault).text).toBe(
      "AWS_ACCESS_KEY_ID={{sec:redacted}}",
    );
  });

  it("keeps the resolved NAME when the secret sits in a key=value position", () => {
    // The shape pass runs after the value pass, so it sees `password={{sec:gh_pat}}`
    // and must not re-mask its own marker into the generic form.
    expect(scrubText("password=" + GH, vault).text).toBe("password={{sec:gh_pat}}");
    expect(scrubText("client_secret: " + GH, vault).text).toBe("client_secret: {{sec:gh_pat}}");
  });

  it("is idempotent — a second scrub changes nothing", () => {
    for (const raw of [
      `password=${GH}`,
      `AWS_ACCESS_KEY_ID=AKIAABCDEFGHIJKLMNOP`,
      `export DATABASE_URL="${DB}"`,
      `key=${GH} and again ${GH}`,
    ]) {
      const once = scrubText(raw, vault).text;
      expect(scrubText(once, vault).text).toBe(once);
    }
  });

  it("can be told to skip shape masking for file reads", () => {
    const line = `aws_secret_access_key = ${DB}`;
    expect(scrubText(line, vault, { shapes: false }).hits).toBe(1);
    expect(scrubText(line, vault, { shapes: false }).text).toContain("{{sec:db_url}}");
    expect(scrubText("AWS_ACCESS_KEY_ID=AKIAABCDEFGHIJKLMNOP", vault, { shapes: false }).hits).toBe(0);
  });
});

describe("scrubDeep", () => {
  it("walks arrays, objects and nested content blocks", () => {
    const input = {
      content: [
        { type: "text", text: `token ${GH}` },
        { type: "text", text: "clean" },
      ],
      details: { nested: { note: DB }, keep: 42, nil: null },
    };
    const out = scrubDeep(input, vault);
    expect(JSON.stringify(out.value)).not.toContain(GH);
    expect(JSON.stringify(out.value)).not.toContain(DB);
    expect(out.value.details.keep).toBe(42);
    expect(out.value.details.nil).toBeNull();
    expect(out.hits).toBe(2);
  });

  it("preserves non-string leaf types", () => {
    const out = scrubDeep({ a: 1, b: true, c: ["x", 2] }, vault);
    expect(out.value).toEqual({ a: 1, b: true, c: ["x", 2] });
  });
});

describe("looksCredentialish", () => {
  it("flags entropy-bearing strings", () => {
    expect(looksCredentialish("ghp_A1b2C3d4E5f6G7h8I9j0K1L2M3N4O5P6Q7R8")).toBe(true);
  });
  it("does not flag git SHAs or prose", () => {
    expect(looksCredentialish("4f9c1a7e2b8d0a3c5e7f1b3d9a2c4e6f8b0d2a4c")).toBe(false);
    expect(looksCredentialish("the quick brown fox jumps over the lazy dog")).toBe(false);
  });
});
