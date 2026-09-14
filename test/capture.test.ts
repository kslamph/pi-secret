import { describe, expect, it } from "vitest";
import { applyCapture, Candidate, CapturedItem, findCandidates, suggestName, suggestNames } from "../src/capture.ts";
import { isValidName } from "../src/refs.ts";

const GH = "ghp_A1b2C3d4E5f6G7h8I9j0K1L2M3N4O5P6Q7R8";
const SHA = "4f9c1a7e2b8d0a3c5e7f1b3d9a2c4e6f8b0d2a4c";
const AKIA = "AKIAABCDEFGHIJKLMNOP";

// Build applyCapture items (candidate<->name pairs). Introduced in round 4 when applyCapture
// stopped taking a per-candidate `nameFor` callback: the old `() => names.shift()!` form was the
// desynchronisable shape that let a name drift onto the wrong candidate. Pairs can't.
const pair = (cs: Candidate[], names: string | string[]): CapturedItem[] =>
  cs.map((c, i) => ({ candidate: c, name: typeof names === "string" ? names : names[i]! }));

describe("findCandidates", () => {
  it("detects an anchored prefix token in prose", () => {
    const cs = findCandidates(`use this for the staging deploy: ${GH}`);
    expect(cs).toHaveLength(1);
    expect(cs[0]).toMatchObject({ value: GH, confidence: "anchored", hint: "github" });
  });

  it("detects key=value shapes", () => {
    const cs = findCandidates("db_password=Tr0ub4dor3xyzabcQ");
    expect(cs).toHaveLength(1);
    expect(cs[0]).toMatchObject({ confidence: "kv", value: "Tr0ub4dor3xyzabcQ", hint: "db_password" });
  });

  it("prefers an anchored provider match when a key=value shape also fits", () => {
    // GITHUB_TOKEN=ghp_... matches BOTH patterns. Anchored must win: it carries
    // the provider hint and cannot mis-slice, and dedupe keeps the earlier,
    // equally-wide match. Verified against the compiled collectors.
    const cs = findCandidates(`GITHUB_TOKEN=${GH}`);
    expect(cs).toHaveLength(1);
    expect(cs[0]).toMatchObject({ confidence: "anchored", hint: "github", value: GH });
  });

  it("never flags a git SHA even when it is high entropy", () => {
    expect(findCandidates(`revert ${SHA} and re-push`)).toEqual([]);
  });

  it("never re-captures an existing ref", () => {
    expect(findCandidates(`use {{sec:gh_staging_token}} here`)).toEqual([]);
  });

  it("detects a bare high-entropy string only at entropy confidence", () => {
    const cs = findCandidates("the key is Xk9#vQ2zLm7$Wr4tYp8nB3sD6fHj");
    expect(cs.length).toBe(1);
    expect(cs[0]?.confidence).toBe("entropy");
  });

  it("handles multiple secrets in one message", () => {
    const cs = findCandidates(`${GH} and aws AKIAABCDEFGHIJKLMNOP done`);
    expect(cs.map((c) => c.hint)).toEqual(expect.arrayContaining(["github", "aws_access_key_id"]));
  });

  it("ignores URLs, paths and version strings", () => {
    expect(findCandidates("https://api.github.com/repos/x/y#main node_modules/v1.2.3-beta.4")).toEqual([]);
  });

  // --- Requirement A: KV value class must align with Task 5's (allow & and \) and
  // must not leave a tail behind. These are RED against the brief's shipped code.
  it("captures a KV value containing & with no tail left behind", () => {
    const text = "password=Tr0ub4dor&xyzabcDEF and more";
    const cs = findCandidates(text);
    expect(cs).toHaveLength(1);
    expect(cs[0]?.value).toBe("Tr0ub4dor&xyzabcDEF");
    expect(cs[0]?.confidence).toBe("kv");
    const out = applyCapture(text, pair(cs, "pw"));
    expect(out.text).toBe("password={{sec:pw}} and more");
    expect(out.text).not.toContain("xyzabcDEF");
    expect(out.captured).toHaveLength(1);
  });

  it("captures a KV value containing a backslash with no tail left behind", () => {
    const text = "token=AbC123\\xyZ789secret and more";
    const cs = findCandidates(text);
    expect(cs).toHaveLength(1);
    expect(cs[0]?.value).toBe("AbC123\\xyZ789secret");
    expect(cs[0]?.confidence).toBe("kv");
    const out = applyCapture(text, pair(cs, "tk"));
    expect(out.text).toBe("token={{sec:tk}} and more");
    expect(out.text).not.toContain("xyZ789secret");
    expect(out.captured).toHaveLength(1);
  });
});

describe("suggestName", () => {
  it("derives a name from hint and nearby context", () => {
    const c = findCandidates(`use this for the staging deploy: ${GH}`)[0]!;
    expect(suggestName(c, `use this for the staging deploy: ${GH}`, [])).toBe("gh_staging_deploy");
    // Stale expectation: the implementation joins the provider hint with up to TWO context
    // words (present.slice(0, 2)). "gh_staging" predated that.
  });

  it("appends a counter on collision", () => {
    const c = findCandidates(GH)[0]!;
    expect(suggestName(c, GH, ["gh"])).toBe("gh-2");
    expect(suggestName(c, GH, ["gh", "gh-2"])).toBe("gh-3");
    // The base derived from the bare token is "gh", so the collision must be against "gh".
    // Asserting "gh_token-2" tested nothing: that name was never in `taken`, so the counter
    // path never ran and the assertion held for any implementation.
  });

  it("always returns a valid name", () => {
    const c = findCandidates("Xk9#vQ2zLm7$Wr4tYp8nB3sD6fHj")[0]!;
    expect(suggestName(c, "Xk9#vQ2zLm7$Wr4tYp8nB3sD6fHj", [])).toMatch(/^[a-z][a-z0-9_-]{0,63}$/);
  });

  it("always returns a valid name even for adversarial hint/context", () => {
    const base = findCandidates("Xk9#vQ2zLm7$Wr4tYp8nB3sD6fHj")[0]!;
    const cases = [
      "🔥".repeat(50) + " 测试 unicode ܒܝܬ",
      "",
      Array.from({ length: 500 }, (_, i) => `word${i}`).join(" "),
    ];
    for (const ctx of cases) {
      const name = suggestName(base, ctx, []);
      expect(isValidName(name)).toBe(true);
      expect(name).toMatch(/^[a-z][a-z0-9_-]{0,63}$/);
    }
  });
});

describe("applyCapture", () => {
  it("replaces every candidate with its ref token", () => {
    const text = `deploy with ${GH} now`;
    const cs = findCandidates(text);
    const out = applyCapture(text, pair(cs, "gh_token"));
    expect(out.text).toBe("deploy with {{sec:gh_token}} now");
    expect(out.captured).toHaveLength(1);
  });

  it("replaces in one pass so earlier offsets stay valid", () => {
    const text = `${GH} and AKIAABCDEFGHIJKLMNOP`;
    const cs = findCandidates(text);
    const names = ["a", "b"];
    const out = applyCapture(text, pair(cs, names));
    expect(out.text).toBe("{{sec:a}} and {{sec:b}}");
  });

  // --- Requirement B: the bare-entropy fallback must capture EVERY occurrence, not
  // just the first (text.indexOf returns only the first index). RED against shipped code.
  it("captures every occurrence of a bare high-entropy token, not just the first", () => {
    const tok = "Lk2#mP9qWw8$Xy5zB3nVc7Rf1Jh4";
    const text = `first ${tok} then ${tok} again`;
    const cs = findCandidates(text);
    expect(cs).toHaveLength(2);
    expect(cs.map((c) => c.confidence)).toEqual(["entropy", "entropy"]);
    const out = applyCapture(text, pair(cs, "sec"));
    expect(out.text).toBe("first {{sec:sec}} then {{sec:sec}} again");
    expect(out.text).not.toContain(tok);
    expect(out.captured).toHaveLength(2);
  });

  // --- Requirement A (over-capture, intentional): a future "fix" that reintroduces a
  // tail must delete this intentional assertion rather than a silent one. Capturing the
  // whole whitespace-free token (even when it mangles a chained command) is the accepted
  // direction, because a mangled submission is visible and reversible while a leaked tail
  // is neither.
  it("intentionally over-captures a chained-command value as one token", () => {
    const text = "password=abc&&echo leaked";
    const cs = findCandidates(text);
    expect(cs).toHaveLength(1);
    expect(cs[0]?.value).toBe("abc&&echo");
    expect(cs[0]?.confidence).toBe("kv");
    const out = applyCapture(text, pair(cs, "pw"));
    expect(out.text).toBe("password={{sec:pw}} leaked");
    expect(out.text).not.toContain("&&echo");
  });
});

// ===== Round 2: quoted values (C) and context windowing (D) =====

describe("round 2 — quoted credential values (Requirement C)", () => {
  it("captures a double-quoted value containing whitespace as one candidate", () => {
    const text = 'password="hunter2 zebra99"';
    const cs = findCandidates(text);
    expect(cs).toHaveLength(1);
    expect(cs[0]?.confidence).toBe("kv");
    expect(cs[0]?.value).toBe("hunter2 zebra99");
    const out = applyCapture(text, pair(cs, "pw"));
    // No fragment of the secret remains; the surrounding quotes are not the secret.
    expect(out.text).toBe('password="{{sec:pw}}"');
    expect(out.text).not.toContain("hunter2");
    expect(out.text).not.toContain("zebra99");
    expect(out.captured).toHaveLength(1);
  });

  it("captures a single-quoted value containing whitespace as one candidate", () => {
    const text = "password='sup secret 42xx'";
    const cs = findCandidates(text);
    expect(cs).toHaveLength(1);
    expect(cs[0]?.confidence).toBe("kv");
    expect(cs[0]?.value).toBe("sup secret 42xx");
    const out = applyCapture(text, pair(cs, "pw"));
    expect(out.text).toBe("password='{{sec:pw}}'");
    expect(out.text).not.toContain("secret");
    expect(out.text).not.toContain("42xx");
  });

  it("yields no candidate for an unclosed quote rather than a fragment", () => {
    // A partial capture is the failure mode requirement A exists to eliminate; an
    // unclosed quote therefore matches neither the quoted nor the bare form.
    expect(findCandidates('password="hunter2 zebra99')).toEqual([]);
    expect(findCandidates("password='sup secret 42xx")).toEqual([]);
  });

  it("captures a quoted value with no internal whitespace identically to the unquoted case", () => {
    const bare = findCandidates("password=secret123")[0]!;
    const quoted = findCandidates('password="secret123"')[0]!;
    expect(bare?.value).toBe("secret123");
    expect(quoted?.value).toBe("secret123");
    const outBare = applyCapture("password=secret123", pair([bare], "pw")).text;
    const outQuoted = applyCapture('password="secret123"', pair([quoted], "pw")).text;
    expect(outBare).toBe("password={{sec:pw}}");
    expect(outQuoted).toBe('password="{{sec:pw}}"');
  });
});

describe("round 2 — name from neighborhood, not whole message (Requirement D)", () => {
  it("names each secret from its own neighborhood on a multi-secret line", () => {
    const GH = "ghp_A1b2C3d4E5f6G7h8I9j0K1L2M3N4O5P6Q7R8";
    const AKIA = "AKIAABCDEFGHIJKLMNOP";
    // >60 chars of filler keep `aws` outside the GitHub token's +/-60 window.
    const filler = " fill ".repeat(30);
    const line = `gh: ${GH}${filler} aws: ${AKIA}`;
    const ghC = findCandidates(line).find((c) => c.hint === "github")!;
    const awsC = findCandidates(line).find((c) => c.hint === "aws_access_key_id")!;
    const ghName = suggestName(ghC, line, []);
    const awsName = suggestName(awsC, line, []);
    expect(ghName).not.toContain("aws");
    expect(awsName).not.toContain("gh");
  });

  it("without windowing this would have named the GitHub token gh_aws (regression guard)", () => {
    const GH = "ghp_A1b2C3d4E5f6G7h8I9j0K1L2M3N4O5P6Q7R8";
    const AKIA = "AKIAABCDEFGHIJKLMNOP";
    const filler = " fill ".repeat(30);
    const line = `gh: ${GH}${filler} aws: ${AKIA}`;
    const ghC = findCandidates(line).find((c) => c.hint === "github")!;
    // The window is centered on the candidate; assert the window itself excludes `aws`.
    expect(line.slice(Math.max(0, ghC.start - 60), ghC.end + 60).includes("aws")).toBe(false);
  });
});

// ===== Round 3: batch naming — distinct by construction (E) and idempotence (F) =====

describe("round 3 — batch naming (Requirements E and F)", () => {
  const A = "Lk2#mP9qWw8$Xy5zB3nVc7Rf1Jh4"; // distinct 28-char high-entropy bare token
  const B = "Qw8$Zp3mK2xL9vB4nC7jR6fD1hS5tY"; // distinct 28-char high-entropy bare token

  it("gives two distinct bare secrets distinct names with no caller threading of taken", () => {
    const text = `here you go: ${A} and ${B}`;
    const cs = findCandidates(text);
    expect(cs.length).toBe(2);
    const names = suggestNames(cs, text); // caller passes no `taken`
    expect(names).toHaveLength(2);
    expect(new Set(names).size).toBe(2); // the dup-name footgun: both want "secret"
    expect(names[0]).not.toBe(names[1]);
  });

  it("names adjacent secrets without leaking the neighbour's keyword", () => {
    // No filler: the two secrets sit 6 chars apart, exactly the realistic paste shape.
    const line = `gh: ${GH}  aws: ${AKIA}`;
    const cs = findCandidates(line);
    const names = suggestNames(cs, line);
    const ghIdx = cs.findIndex((c) => c.hint === "github");
    expect(ghIdx).toBeGreaterThanOrEqual(0);
    expect(names[ghIdx]).not.toContain("aws");
  });

  it("reuses a known value's vault name unchanged (F)", () => {
    const text = `token is ${GH}`;
    const cs = findCandidates(text);
    const names = suggestNames(cs, text, {
      existingNameForValue: (v) => (v === GH ? "gh_my_existing" : undefined),
    });
    expect(names[0]).toBe("gh_my_existing");
  });

  it("gives five mixed candidates five pairwise-distinct valid names", () => {
    const text = `${GH} and aws ${AKIA} also db_password=Tr0ub4dor3xyzabcQ and ${A} finally ${B}`;
    const cs = findCandidates(text);
    const names = suggestNames(cs, text);
    expect(names).toHaveLength(cs.length);
    expect(new Set(names).size).toBe(cs.length);
    for (const n of names) expect(isValidName(n)).toBe(true);
  });

  it("emits distinct refs in applyCapture when values differ (the missing assertion)", () => {
    const text = `here you go: ${A} and ${B}`;
    const cs = findCandidates(text);
    const names = suggestNames(cs, text);
    const nameOf = new Map(cs.map((c, idx) => [c, names[idx]!]));
    const out = applyCapture(text, cs.map((c) => ({ candidate: c, name: nameOf.get(c)! })));
    const refs = [...out.text.matchAll(/\{\{sec:([a-z][a-z0-9_-]{0,63})\}\}/g)].map((m) => m[1]!);
    expect(new Set(refs).size).toBe(2);
    expect(out.captured).toHaveLength(2);
  });
});

// ===== Round 4: KV value hygiene (G), wrong-credential guards (H, I), keyword closure (J) =====
// G and J are PINS: the partial tree already implements them, so these do not go RED. They lock
// the probed behaviour so a future edit cannot regress it. The negative controls (monkey=/etc.)
// are recorded verbatim so a keyword widening cannot silently start matching them.

describe("round 4 — KV value delimiter trimming (Requirement G, pins)", () => {
  it("trims a stray trailing quote from a bare KV value", () => {
    const cs = findCandidates('password=secret123"');
    expect(cs).toHaveLength(1);
    expect(cs[0]?.value).toBe("secret123");
    const out = applyCapture('password=secret123"', pair(cs, "pw"));
    expect(out.text).toBe('password={{sec:pw}}"');
    expect(out.text).not.toContain("secret123");
  });

  it("trims a trailing comma", () => {
    const cs = findCandidates("password=abc12345,");
    expect(cs).toHaveLength(1);
    expect(cs[0]?.value).toBe("abc12345");
  });

  it("trims a leading AND trailing parenthesis, leaving the parens in the text", () => {
    const cs = findCandidates("password=(abc12345)");
    expect(cs).toHaveLength(1);
    expect(cs[0]?.value).toBe("abc12345");
    const out = applyCapture("password=(abc12345)", pair(cs, "pw"));
    expect(out.text).toBe("password=({{sec:pw}})");
  });

  it("preserves base64 padding (=) and word separators (-, _) inside the value", () => {
    const cs = findCandidates("password=YWJjZGVmZ2g=");
    expect(cs).toHaveLength(1);
    expect(cs[0]?.value).toBe("YWJjZGVmZ2g=");
  });

  it("trims backticks from a bare KV value", () => {
    const cs = findCandidates(`token=\`${GH}\``);
    expect(cs).toHaveLength(1);
    expect(cs[0]?.value).toBe(GH);
    const out = applyCapture(`token=\`${GH}\``, pair(cs, "tk"));
    expect(out.text).toBe("token=`{{sec:tk}}`");
  });

  it("trims sentence punctuation (. , ; : ! ?) from both ends", () => {
    expect(findCandidates("password=abc12345.")[0]?.value).toBe("abc12345");
    expect(findCandidates("password=abc12345;")[0]?.value).toBe("abc12345");
    expect(findCandidates("password=abc12345:")[0]?.value).toBe("abc12345");
  });

  it("leaves angle-bracket placeholders uncaptured (delimiters excluded on purpose)", () => {
    expect(findCandidates("password=<placeholder>")).toEqual([]);
  });
});

describe("round 4 — keyword boundary closure (Requirement J, pins)", () => {
  it("captures a token= legacy 40-hex PAT (deny list is entropy-only now)", () => {
    const hex40 = "0123456789abcdef0123456789abcdef01234567";
    const cs = findCandidates(`token=${hex40}`);
    expect(cs).toHaveLength(1);
    expect(cs[0]?.value).toBe(hex40);
    expect(cs[0]?.confidence).toBe("kv");
  });

  it("captures a full connection-string value behind DATABASE_URL", () => {
    const url = "postgres://user:pWss@db.internal:5432/app";
    const cs = findCandidates(`DATABASE_URL=${url}`);
    expect(cs).toHaveLength(1);
    expect(cs[0]?.value).toBe(url);
  });

  it("captures my_key= but not monkey=, turnkey=, keyboard= (negative controls)", () => {
    expect(findCandidates("my_key=supersecret99")).toHaveLength(1);
    expect(findCandidates("monkey=supersecret99")).toEqual([]);
    expect(findCandidates("turnkey=supersecret99")).toEqual([]);
    expect(findCandidates("keyboard=supersecret99")).toEqual([]);
  });

  it("does not deny a bare 40-hex blob with no key (entropy deny still applies)", () => {
    const hex40 = "0123456789abcdef0123456789abcdef01234567";
    expect(findCandidates(`revert ${hex40} and re-push`)).toEqual([]);
  });
});

describe("round 4 — wrong-credential guards (Requirements H and I)", () => {
  // H: span mismatch must skip, never rewrite under a possibly-wrong name.
  it("applyCapture skips a candidate whose span no longer matches its value", () => {
    const text = `deploy ${GH}`;
    const cs = findCandidates(text);
    const c = cs[0]!;
    const bad: CapturedItem = { candidate: { ...c, value: "not-the-value" }, name: "x" };
    const out = applyCapture(text, [bad]);
    expect(out.captured).toHaveLength(0);
    expect(out.text).toBe(text);
  });

  // H invariant for Task 10 wiring: `captured` is the only thing that should hit the vault, and
  // every captured pair really was substituted under its own name.
  it("captured pairs reflect exactly what was substituted", () => {
    const text = `one ${GH} two ${AKIA}`;
    const cs = findCandidates(text);
    const names = suggestNames(cs, text);
    const items = cs.map((c, i) => ({ candidate: c, name: names[i]! }));
    const out = applyCapture(text, items);
    expect(out.captured).toHaveLength(cs.length);
    expect(out.captured.every((p) => text.slice(p.candidate.start, p.candidate.end) === p.candidate.value)).toBe(true);
  });

  // I: two distinct secrets must never share a name, even if existingNameForValue collides.
  it("I: two distinct secrets get distinct names even when existingNameForValue collides", () => {
    const A = "Lk2#mP9qWw8$Xy5zB3nVc7Rf1Jh4";
    const B = "Qw8$Zp3mK2xL9vB4nC7jR6fD1hS5tY";
    const text = `here ${A} and ${B}`;
    const cs = findCandidates(text);
    const names = suggestNames(cs, text, { existingNameForValue: (v) => (v === B ? "secret" : undefined) });
    expect(names).toHaveLength(2);
    expect(names[0]).not.toBe(names[1]);
    expect(new Set(names).size).toBe(2);
  });

  // I: a reused name that fails isValidName is regenerated, never passed through.
  it("I: an invalid reused name is validated and regenerated, never passed through", () => {
    const text = `token ${GH}`;
    const cs = findCandidates(text);
    const names = suggestNames(cs, text, { existingNameForValue: () => "Bad Name!" });
    expect(names[0]).not.toBe("Bad Name!");
    expect(isValidName(names[0]!)).toBe(true);
  });

  // I: aliasing — one value appearing twice gets one reused name for both.
  it("I: aliasing — one value twice yields one reused name for both (F preserved)", () => {
    const text = `see ${GH} also ${GH}`;
    const cs = findCandidates(text);
    const names = suggestNames(cs, text, { existingNameForValue: () => "saved" });
    expect(names).toEqual(["saved", "saved"]);
  });

  // I: final assertion — two DISTINCT values must not share a reused name.
  it("I: asserts when two distinct values would share a reused name", () => {
    const A = "Lk2#mP9qWw8$Xy5zB3nVc7Rf1Jh4";
    const B = "Qw8$Zp3mK2xL9vB4nC7jR6fD1hS5tY";
    const text = `here ${A} and ${B}`;
    const cs = findCandidates(text);
    expect(() => suggestNames(cs, text, { existingNameForValue: () => "secret" })).toThrow();
  });
});
