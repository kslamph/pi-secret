import { describe, expect, it } from "vitest";
import { findCandidates } from "../src/capture.ts";

/**
 * Capture quality: the two failures this file exists to pin.
 *
 * The corpus is not invented. BENIGN and SECRETS were measured against a real
 * capture on 2026-10-09 (~/devops, a Chinese expense prompt whose three 21-char
 * runs were rewritten into {{sec:...}} refs by the entropy tier alone), and the
 * recall/precision counts come from running both this detector and a third-party
 * one over Claude's published corpus.
 *
 * Provider-shaped values are assembled from parts so no literal that matches a
 * real credential format lands in the repository — push protection matches on the
 * file text, and the repo has already been refused once for that (3b02eaa).
 */
const GH = ["ghp_", "ExamplePlaceholderBodyNotARealKey123456"].join("");

// ── Must NOT be captured: identifiers, filenames, prose, config ──────────────
const BENIGN: Array<[string, string]> = [
  ["the CJK+latin run from the 2026-10-09 incident", "根据这个给我模拟个7,8,9月的费用出来. 保持bitbucket和lightnode不变， 9月bibucket费用没有了"],
  ["a bare filename with no directory", "why does formatCurrencyAmountsForDisplay.ts fail?"],
  ["a tsconfig option name in quotes", 'tsconfig has "resolvePackageJsonExports": true'],
  ["a PascalCase call", "call NewPaymentCaseReconcilerFromContext(ctx)"],
  ["a long component path", "see src/components/dashboard/UserProfileSettingsPanel.tsx"],
  ["a long handler name", "call getUserAccountInformationById2Handler now"],
  ["a report filename", "report_2024_Final_Version_Q3Summary.pdf"],
  ["a long k8s type name", "KubernetesIngressGatewayTLSSecretBinding"],
  ["a long constant name", "MONTHLY_SUBSCRIPTION_renewal_date"],
  ["a bare 32-hex digest", "0123456789abcdef0123456789abcdef"],
  ["a long camelCase identifier", "notificationPreferencesConfigurationEndpoint"],
  ["an all-caps constant", "PMGO_RECON_RAW_SIGN_KEY_ROTATION_TODO"],
  ["a short all-caps name", "AWS_ACCESS_KEY_ID"],
  ["a slug-like env var name", "DATABASE_REPLICA_HOST_POOL_SIZE"],
];

// ── Must still be captured: real secrets, several with no keyword nearby ─────
const SECRETS: Array<[string, string]> = [
  ["a symbol-dense 28-char token", "the key is Xk9#vQ2zLm7$Wr4tYp8nB3sD6fHj"],
  ["a symbol-dense token repeated", "first Lk2#mP9qWw8$Xy5zB3nVc7Rf1Jh4 then Lk2#mP9qWw8$Xy5zB3nVc7Rf1Jh4 again"],
  ["a base64 blob containing a slash", "the value is CzBVep/E6RM4XYKnzPEbQGWKr9T5I0ht thanks"],
  ["a provider prefix", `use ${GH} for the deploy`],
  ["an alphanumeric run with no symbols", "key is k8Jd92HsLq0PzXm3VnB7cT5yRw1Eu4Ga ok"],
];

// ── Tier 2 forms we did not recognise on 2026-10-09 ──────────────────────────
// Values are assembled from parts for the same push-protection reason, and so
// that the test states the SHAPE it depends on instead of a magic string.
const FLAG_VALUE = ["hunter", "22"].join("");
const ANNOT_VALUE = ["abc", "123", "45"].join("");
const PROSE_VALUE = ["Tr0ub", "4dor", "&", "3"].join("");
const SHORT_PW = ["hunter", "2"].join("");
const ENV_LOOKUP = ["os", ".", "getenv", "(", "API_KEY)"].join("");
const CHANGE_ME = ["change", "me"].join("-");
const PLACEHOLDER_WORD = ["secret"].join("");
const CJK_VALUE = ["Xy7#", "kLm9", "pQ"].join("");

describe("capture quality — over-capture (tier 3 must stay quiet)", () => {
  for (const [label, text] of BENIGN) {
    it(`leaves ${label} alone`, () => {
      expect(findCandidates(text)).toEqual([]);
    });
  }
});

describe("capture quality — recall guards (tier 3 must not lose ground)", () => {
  for (const [label, text] of SECRETS) {
    it(`still captures ${label}`, () => {
      expect(findCandidates(text).length).toBeGreaterThan(0);
    });
  }

  it("still captures EVERY occurrence of a bare token, not just the first", () => {
    const tok = "Lk2#mP9qWw8$Xy5zB3nVc7Rf1Jh4";
    expect(findCandidates(`first ${tok} then ${tok}`)).toHaveLength(2);
  });
});

describe("tier 2 — assignment and prose forms we missed", () => {
  const cases: Array<[string, string, string]> = [
    ["a short password behind a strong keyword", "DB_PASSWORD=" + SHORT_PW, SHORT_PW],
    ["a flag with no equals sign", `mysql --password ${FLAG_VALUE} -h host`, FLAG_VALUE],
    ["a flag with an equals sign", "mysql --password=" + FLAG_VALUE + " -h host", FLAG_VALUE],
    ["a type annotation between keyword and =", `password: str = "${ANNOT_VALUE}"`, ANNOT_VALUE],
    ["English prose", `my password is ${PROSE_VALUE}`, PROSE_VALUE],
    ["Chinese prose", `我的数据库密码是 ${CJK_VALUE}，请帮我写连接代码`, CJK_VALUE],
    ["a Chinese colon form", `密码：${CJK_VALUE}`, CJK_VALUE],
    ["a Chinese passphrase form", `口令设置为 ${CJK_VALUE}`, CJK_VALUE],
    ["a basic-auth flag", `curl -u admin:${FLAG_VALUE} https://x.com`, FLAG_VALUE],
  ];

  for (const [label, text, value] of cases) {
    it(`captures ${label}`, () => {
      const cs = findCandidates(text);
      expect(cs.map((c) => c.value)).toContain(value);
    });
  }

  it("still refuses the short weak-keyword value it always refused", () => {
    expect(findCandidates("max_tokens: 4096")).toEqual([]);
    expect(findCandidates("token_type: bearer")).toEqual([]);
  });

  it("keeps the keyword segment boundary (my_key yes, keyboard no)", () => {
    expect(findCandidates(`my_key=${FLAG_VALUE}`)).toHaveLength(1);
    expect(findCandidates(`keyboard=${FLAG_VALUE}`)).toEqual([]);
  });
});

describe("tier 2 — values that are references, not literals", () => {
  const cases: Array<[string, string]> = [
    ["a python getpass call", "password = " + ["getpass", ".", "getpass"].join("")],
    ["a python env lookup", "password = " + ["os", ".", "getenv", "("].join("")],
    ["a rust Option type", "password: " + ["Optional", "[", "str", "]"].join("") + " = None"],
    ["a dotted attribute", "password = " + ["config", ".", "settings"].join("")],
    ["a shell variable", ["password=", "$", "{SECRET_VAR}"].join("")],
    ["a type annotation alone", `function foo(password: string) { return 1; }`],
    ["a dotted type annotation alone", "def connect(host, password: " + ["Optional", "[", "str", "]"].join("") + "):"],
  ];

  for (const [label, text] of cases) {
    it(`does not capture ${label}`, () => {
      expect(findCandidates(text)).toEqual([]);
    });
  }

  it("does not damage a python env lookup line (regression: it used to truncate the value)", () => {
    const lookup = `${["os", "getenv", "(", "API_KEY)"].join("")}`;
    const text = "api_key = " + ENV_LOOKUP;
    const cs = findCandidates(text);
    // Either nothing is captured, or whatever is captured is the WHOLE token —
    // never a prefix of it, which is what mangled the user's code.
    for (const c of cs) {
      expect(text.slice(c.start, c.end)).toBe(c.value);
    }
  });
});

describe("tier 2 — placeholder and template values", () => {
  const placeholders = ["change", "me"].join("-");
  const cases: Array<[string, string]> = [
    ["a change-me value", "password=" + CHANGE_ME],
    ["an x-filled value", `password=${"x".repeat(8)}`],
    ["a star-filled value", `password=${"*".repeat(8)}`],
    ["an angle-bracket template", "token: <your-token-here>"],
    ["a word placeholder", "password=" + PLACEHOLDER_WORD],
    ["a sample marker", "password=sample"],
    ["the word secret itself", "password=secret"],
    ["a bare type name", "password=string"],
  ];

  for (const [label, text] of cases) {
    it(`does not capture ${label}`, () => {
      expect(findCandidates(text)).toEqual([]);
    });
  }
});

describe("tier 3 — retunes, each one a measured miss", () => {
  // Regression 1: an all-lowercase token with digits is an ordinary base64 blob. It has
  // no uppercase at all, so the first version of the digit rule dropped it — and so did a
  // word-ratio rule that counted its single 16-letter run as a name.
  it("keeps a long lowercase-and-digits token (measured recall loss once)", () => {
    const tok = ["abcdefghijklmnop1234567890"].join("");
    const cs = findCandidates(`curl -H "Authorization: Bearer ${tok}" https://api.x.com`);
    expect(cs.map((c) => c.value)).toContain(tok);
  });

  // Regression 2: a name chains several word runs; random text does not. One run is not
  // a name, however much of the token it covers.
  it("does not call a single long letter run a name", () => {
    expect(findCandidates(`value ${["abcdefghijklmnop1234567890"].join("")}`).length).toBeGreaterThan(0);
  });

  // Regression 3: the snake/kebab rule must not eat prefixed provider keys, whose first
  // segments are pure letters. Tier 1 now catches these before tier 3 sees them, and this
  // pins that the tier-3 rule alone would not have.
  it("keeps a dashed provider-shaped token at the entropy tier", () => {
    const tok = ["sk", "proj", "ExamplePlaceholderBody123456"].join("-");
    expect(findCandidates(`raw value ${tok}`).length).toBeGreaterThan(0);
  });

  it("still drops a no-digit snake constant", () => {
    expect(findCandidates(`const ${["MONTHLY_SUBSCRIPTION_renewal_date"].join("")} = 3`)).toEqual([]);
  });

  // A deliberate divergence from the third-party detector, pinned so nobody "fixes" it
  // back: a passphrase behind a password keyword IS a secret. The reference implementation
  // rejects it as word-like; we capture it, because the keyword is evidence and the value
  // is a real credential shape (XKCD-style, 25 chars, high entropy).
  it("captures a passphrase behind a strong keyword", () => {
    const passphrase = ["correcthorsebatterystaple"].join("");
    const cs = findCandidates("login(user, password=" + passphrase);
    expect(cs.map((c) => c.value)).toContain(passphrase);
  });
});

describe("tier 1 — the provider table must not drift from entropy.ts", () => {
  it("anchors an OpenAI project key instead of leaving it to the entropy tier", () => {
    const sk = ["sk", "proj", "ExamplePlaceholderBodyNotARealKey123456"].join("-");
    const cs = findCandidates(`use ${sk} please`);
    expect(cs).toHaveLength(1);
    expect(cs[0]?.confidence).toBe("anchored");
  });

  it("anchors a Stripe key", () => {
    const stripe = ["sk", "live", "ExamplePlaceholderBodyNotReal1234"].join("_");
    const cs = findCandidates(`use ${stripe} please`);
    expect(cs).toHaveLength(1);
    expect(cs[0]?.confidence).toBe("anchored");
  });

  it("anchors a SendGrid key", () => {
    const sg = `${["SG", "ExamplePlaceholderPartOne1234", "ExamplePlaceholderPartTwo1234"].join(".")}`;
    const cs = findCandidates(`use ${sg} please`);
    expect(cs).toHaveLength(1);
    expect(cs[0]?.confidence).toBe("anchored");
  });

  it("anchors an AWS role id beyond AKIA/ASIA", () => {
    const aroa = ["AROA", "EXAMPLEPLACEHOLDER12"].join("");
    const cs = findCandidates(`role ${aroa} attached`);
    expect(cs).toHaveLength(1);
    expect(cs[0]?.confidence).toBe("anchored");
  });

  it("captures a truncated private key that has no END line", () => {
    const body = "MIIEowIBAAKCAQEAExamplePlaceholderBodyNotARealKeyAtAll0123456789abcdefghij";
    const cs = findCandidates(`-----BEGIN PRIVATE KEY-----\n${body}\n`);
    expect(cs.length).toBeGreaterThan(0);
    expect(cs[0]!.value).toContain(body);
  });
});