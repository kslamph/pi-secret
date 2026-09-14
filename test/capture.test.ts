import { describe, expect, it } from "vitest";
import { applyCapture, Candidate, CapturedItem, findCandidates, suggestNameForTest, suggestNames } from "../src/capture.ts";
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

describe("suggestNameForTest", () => {
  it("derives a name from hint and nearby context", () => {
    const c = findCandidates(`use this for the staging deploy: ${GH}`)[0]!;
    expect(suggestNameForTest(c, `use this for the staging deploy: ${GH}`, [])).toBe("gh_staging_deploy");
    // Stale expectation: the implementation joins the provider hint with up to TWO context
    // words (present.slice(0, 2)). "gh_staging" predated that.
  });

  it("appends a counter on collision", () => {
    const c = findCandidates(GH)[0]!;
    expect(suggestNameForTest(c, GH, ["gh"])).toBe("gh-2");
    expect(suggestNameForTest(c, GH, ["gh", "gh-2"])).toBe("gh-3");
    // The base derived from the bare token is "gh", so the collision must be against "gh".
    // Asserting "gh_token-2" tested nothing: that name was never in `taken`, so the counter
    // path never ran and the assertion held for any implementation.
  });

  it("always returns a valid name", () => {
    const c = findCandidates("Xk9#vQ2zLm7$Wr4tYp8nB3sD6fHj")[0]!;
    expect(suggestNameForTest(c, "Xk9#vQ2zLm7$Wr4tYp8nB3sD6fHj", [])).toMatch(/^[a-z][a-z0-9_-]{0,63}$/);
  });

  it("always returns a valid name even for adversarial hint/context", () => {
    const base = findCandidates("Xk9#vQ2zLm7$Wr4tYp8nB3sD6fHj")[0]!;
    const cases = [
      "🔥".repeat(50) + " 测试 unicode ܒܝܬ",
      "",
      Array.from({ length: 500 }, (_, i) => `word${i}`).join(" "),
    ];
    for (const ctx of cases) {
      const name = suggestNameForTest(base, ctx, []);
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
    const ghName = suggestNameForTest(ghC, line, []);
    const awsName = suggestNameForTest(awsC, line, []);
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

  // I: an unsatisfiable reuse request must DEGRADE (K), not throw and cost the user their message.
  it("I/K: two distinct values mapped to one reused name degrade to distinct names (no throw)", () => {
    const A = "Lk2#mP9qWw8$Xy5zB3nVc7Rf1Jh4";
    const B = "Qw8$Zp3mK2xL9vB4nC7jR6fD1hS5tY";
    const text = `here ${A} and ${B}`;
    const cs = findCandidates(text);
    const names = suggestNames(cs, text, { existingNameForValue: () => "secret" });
    expect(names).toHaveLength(2);
    expect(new Set(names).size).toBe(2); // degraded to distinct, no throw
    expect(names.filter((n) => n === "secret").length).toBe(1); // caller's name kept for one
    for (const n of names) expect(isValidName(n)).toBe(true);
  });
});

// ===== Round 5: Requirement K — degrade unsatisfiable reuse instead of throwing =====
describe("round 5 — K: degrade unsatisfiable reuse (no throw, caller reuse still honored)", () => {
  // 40 distinct candidates, every one reusing the same vault name "same". The old code threw;
  // K degrades: keep "same" for one, generate 39 distinct valid names. No exception, the user
  // keeps their message.
  const mkCandidates = (n: number): Candidate[] =>
    Array.from({ length: n }, (_, i) => {
      const value = `Tk${String(i).padStart(3, "0")}#mP9qWw8$Xy5zB3nVc7Rf1Jh4ok${i}`;
      return { value, start: i * 40, end: i * 40 + value.length, confidence: "entropy", hint: "" };
    });

  it("40 distinct candidates all reusing one name degrade to 40 distinct valid names (no throw)", () => {
    const cs = mkCandidates(40);
    const names = suggestNames(cs, "", { existingNameForValue: () => "same" });
    expect(names).toHaveLength(40);
    expect(new Set(names).size).toBe(40); // pairwise distinct
    for (const n of names) expect(isValidName(n)).toBe(true);
    // K degradation keeps the caller's name for exactly one candidate; the rest are generated.
    expect(names.filter((n) => n === "same").length).toBe(1);
  });

  // Cannot pass K by ignoring existingNameForValue — a satisfiable reuse must still be honored.
  it("a satisfiable reuse (distinct values, distinct reused names) is still honored", () => {
    const A = "Lk2#mP9qWw8$Xy5zB3nVc7Rf1Jh4";
    const B = "Qw8$Zp3mK2xL9vB4nC7jR6fD1hS5tY";
    const text = `here ${A} and ${B}`;
    const cs = findCandidates(text);
    const names = suggestNames(cs, text, {
      existingNameForValue: (v) => (v === A ? "a_name" : "b_name"),
    });
    expect(names.filter((n) => n === "a_name").length).toBe(cs.filter((c) => c.value === A).length);
    expect(names.filter((n) => n === "b_name").length).toBe(cs.filter((c) => c.value === B).length);
  });
});

// ===== Task 17: capture precision and safety (L-R) =====
// Every fixture below is a measured shape from task-17-brief.md; negative controls are verbatim.

describe("task 17 — L: base64 padding re-attached exactly, not greedily", () => {
  it("stores the full decodable base64 value (with ==) for auth=Basic ...", () => {
    const text = "auth=Basic dXNlcjpwYXNzd29yZDEyMw==";
    const cs = findCandidates(text);
    expect(cs).toHaveLength(1);
    expect(cs[0]!.value).toBe("dXNlcjpwYXNzd29yZDEyMw=="); // 24 chars, not the 22-char corrupt copy
    expect(cs[0]!.value.length % 4).toBe(0); // decodable
    const out = applyCapture(text, pair(cs, "cred"));
    expect(out.text).toBe("auth=Basic {{sec:cred}}");
    expect(out.text).not.toContain("dXNlcjpwYXNzd29yZDEyMw"); // no truncated leaked tail
  });

  it("reattaches exactly the padding present and never an unbounded = run", () => {
    const with2 = findCandidates("see dXNlcjpwYXNzd29yZDEyMw== and more");
    expect(with2).toHaveLength(1);
    expect(with2[0]!.value).toBe("dXNlcjpwYXNzd29yZDEyMw=="); // 24, decodable
    expect(with2[0]!.value.length % 4).toBe(0);
    // three `=` is an unbounded run: the extra `=` must NOT be absorbed (would be invalid base64),
    // so the value stays 22 chars WITHOUT padding rather than corrupting to 25.
    const with3 = findCandidates("see dXNlcjpwYXNzd29yZDEyMw=== and more");
    expect(with3).toHaveLength(1);
    expect(with3[0]!.value).toBe("dXNlcjpwYXNzd29yZDEyMw");
    expect(with3[0]!.value.length % 4).toBe(2);
  });

  it("does NOT treat an unbounded = run as padding (key=dXNlcg=x=y keeps dXNlcg=x=y)", () => {
    const cs = findCandidates("key=dXNlcg=x=y");
    expect(cs).toHaveLength(1);
    expect(cs[0]!.value).toBe("dXNlcg=x=y"); // shell assigns a=b; must stay captured as-is
  });

  it("rejects a len%4===1 residue (no padding) as not valid base64", () => {
    // 21-char base64 with no `=`: pad would be 3, which is invalid, so it is left unpadded.
    const cs = findCandidates("the value is AbCdEfGhIjKlMnOpQrStU now");
    expect(cs).toHaveLength(1);
    expect(cs[0]!.value).toBe("AbCdEfGhIjKlMnOpQrStU");
    expect(cs[0]!.value.length % 4).toBe(1);
  });
});

describe("task 17 — M: bare base64 blob is captured, not silently leaked", () => {
  const blob = "CzBVep/E6RM4XYKnzPEbQGWKr9T5I0ht"; // 24-byte random blob; contains '/'
  it("captures a bare random base64 blob (with /) pasted without a keyword", () => {
    expect(blob).toMatch(/\//); // this is exactly the shape the old token.includes("/") ban dropped
    const cs = findCandidates(`the value is ${blob} thanks`);
    expect(cs).toHaveLength(1);
    expect(cs[0]!.confidence).toBe("entropy");
    expect(cs[0]!.value).toBe(blob);
    const out = applyCapture(`the value is ${blob} thanks`, pair(cs, "blob"));
    expect(out.text).toBe("the value is {{sec:blob}} thanks");
    expect(out.text).not.toContain(blob);
  });
  it("still captures the same blob behind api_key=", () => {
    const cs = findCandidates(`api_key=${blob}`);
    expect(cs).toHaveLength(1);
    expect(cs[0]!.value).toBe(blob);
  });
});

describe("task 17 — N: url= defaults to NOT capturing plain links", () => {
  it("does NOT capture image_url=, download_url=, or url= to a plain https link", () => {
    expect(findCandidates("image_url=https://cdn.example.com/a/b/c.png?v=3 for the logo")).toEqual([]);
    expect(findCandidates("download_url=https://releases.example.com/tool/1.2.3/tool-linux-x86_64.tar.gz")).toEqual([]);
    expect(findCandidates("url=https://example.com")).toEqual([]);
  });
  it("DOES capture DATABASE_URL=postgres://user:pass@host:5432/app (userinfo)", () => {
    const url = "postgres://admin:sup3rsecret@db.internal:5432/app";
    const cs = findCandidates(`DATABASE_URL=${url}`);
    expect(cs).toHaveLength(1);
    expect(cs[0]!.value).toBe(url);
  });
  it("DOES capture a slack webhook URL behind url=", () => {
    const hook = "https://hooks.slack.com/services/T01234567/B01234567/EXAMPLE-NOT-A-REAL-WEBHOOK";
    const cs = findCandidates(`url=${hook}`);
    expect(cs).toHaveLength(1);
    expect(cs[0]!.value).toBe(hook);
  });
  it("does NOT capture a url= link whose only signal is a high-entropy path segment", () => {
    // Refuted proposal: an entropy threshold (tool-linux-x86_64.tar.gz scores 4.00 > 3.9) cannot
    // separate webhooks from downloads; the shape rule (userinfo/host/query) is what gates.
    const dl = "https://releases.example.com/tool/1.2.3/tool-linux-x86_64.tar.gz";
    expect(findCandidates(`url=${dl}`)).toEqual([]);
  });
});

describe("task 17 — O: private-key paths excluded, not captured by keyword luck", () => {
  it("does NOT capture ssh_key=/home/u/.ssh/id_rsa (path-valued)", () => {
    expect(findCandidates("ssh_key=/home/u/.ssh/id_rsa")).toEqual([]);
  });
  it("does NOT capture private_key=/home/u/.ssh/id_rsa", () => {
    expect(findCandidates("private_key=/home/u/.ssh/id_rsa")).toEqual([]);
  });
  it("does NOT capture key=/some/path/id_rsa (id_ basename)", () => {
    expect(findCandidates("key=/some/path/id_rsa")).toEqual([]);
  });
  it("leaves key_file= uncaptured (negative control, no keyword match)", () => {
    expect(findCandidates("key_file=/home/u/.ssh/id_rsa")).toEqual([]);
  });
});

describe("task 17 — P: applyCapture checks name->value consistency and counts skips", () => {
  it("skips a name bound to two distinct values instead of writing one name for both", () => {
    const text = `one ${GH} two ${AKIA}`;
    const cs = findCandidates(text);
    const items: CapturedItem[] = [
      { candidate: cs[0]!, name: "shared" },
      { candidate: cs[1]!, name: "shared" },
    ];
    const out = applyCapture(text, items);
    // exactly one value may carry the name; the conflict is skipped, never collapsed.
    expect(out.captured).toHaveLength(1);
    expect(out.skipped.nameConflict).toBe(1);
    expect(out.skipped.staleSpan).toBe(0);
    expect(new Set(out.captured.map((p) => p.name)).size).toBe(out.captured.length);
    expect(out.captured[0]!.name).toBe("shared");
    expect(out.captured[0]!.candidate.value === GH || out.captured[0]!.candidate.value === AKIA).toBe(true);
  });
  it("counts skips honestly: a stale span yields captured < items and a staleSpan skip", () => {
    const text = `here ${GH}`;
    const cs = findCandidates(text);
    const bad: CapturedItem = { candidate: { ...cs[0]!, value: "not-the-value" }, name: "x" };
    const out = applyCapture(text, [bad]);
    expect(out.captured).toHaveLength(0);
    expect(out.skipped.staleSpan).toBe(1);
    expect(out.skipped.nameConflict).toBe(0);
    expect(out.text).toBe(text);
  });
});

describe("task 17 — Q: singular namer only reachable as suggestNameForTest", () => {
  it("suggestName is no longer exported; suggestNameForTest is", async () => {
    const mod = await import("../src/capture.ts");
    expect((mod as Record<string, unknown>).suggestName).toBeUndefined();
    expect(typeof mod.suggestNameForTest).toBe("function");
  });
});

describe("task 17 — R: key hint preferred, no doubled context words, names not deduped", () => {
  it("names DATABASE_URL without doubling db (database_db_db -> database_url)", () => {
    const url = "postgres://admin:sup3rsecret@db.internal:5432/app";
    const cs = findCandidates(`DATABASE_URL=${url}`);
    const names = suggestNames(cs, `DATABASE_URL=${url}`);
    expect(names[0]).toBe("database_url");
    expect(names[0]).not.toMatch(/db_db/);
  });
  it("does not dedupe or shorten names (same value reuses one name, by construction)", () => {
    const cs = findCandidates(`see ${GH} also ${GH}`);
    const names = suggestNames(cs, `see ${GH} also ${GH}`);
    expect(names).toEqual(["gh", "gh"]); // valueName keyed by value; suffixing stays collision-free
  });
  it("prefers the full key hint (db_password -> db_password, not db)", () => {
    const cs = findCandidates("db_password=Tr0ub4dor3xyzabcQ");
    const names = suggestNames(cs, "db_password=Tr0ub4dor3xyzabcQ");
    expect(names[0]).toBe("db_password");
  });
});

describe("task 17 — S: bare credential-bearing URLs are captured (leak closed)", () => {
  it("captures a bare DSN with userinfo pasted without a url= key", () => {
    const text = "migrate with https://admin:S3cr3tValue@db.internal:5432/app";
    const cs = findCandidates(text);
    expect(cs.length).toBeGreaterThanOrEqual(1);
    expect(cs[0]!.value).toBe("https://admin:S3cr3tValue@db.internal:5432/app");
    expect(cs[0]!.value).toContain("@"); // userinfo, the credential
  });
  it("captures a bare postgres:// DSN with userinfo", () => {
    const text = "connect string postgres://admin:S3cr3tValue@db.internal:5432/app";
    const cs = findCandidates(text);
    expect(cs.length).toBeGreaterThanOrEqual(1);
    expect(cs[0]!.value).toBe("postgres://admin:S3cr3tValue@db.internal:5432/app");
  });
  it("still does NOT capture a benign bare https link (no userinfo / no cred host / no cred query)", () => {
    expect(findCandidates("see https://api.github.com/repos/x/y for details")).toEqual([]);
  });
  it("captures a bare webhook URL (cred host + ingest path) without a url= key", () => {
    const hook = "https://hooks.slack.com/services/T01234567/B01234567/EXAMPLE-NOT-A-REAL-WEBHOOK";
    const cs = findCandidates(`ping ${hook} now`);
    expect(cs.length).toBeGreaterThanOrEqual(1);
    expect(cs[0]!.value).toBe(hook);
  });
});

describe("task 17 — T: PEM bodies and data-URI payloads are NOT vaulted", () => {
  const publicKey =
    "-----BEGIN PUBLIC KEY-----\nMFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBALQZ3vtPqGmZ0jNjF0lNMQA8tZ4tq\nx0jN0kZ1vX0pQwErTyUiOpAsDfGhJkLzXcVbNmQwErTyUiOpAsDfGhJkLzXcVb=\n-----END PUBLIC KEY-----";
  const dataUri = "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCA";
  const privateKey =
    "-----BEGIN PRIVATE KEY-----\nMIIBVgIBADANBgkqhkiG9w0BAQEFAASCAUEwggEBAgECggEBAK4B\n-----END PRIVATE KEY-----";
  const blob = "CzBVep/E6RM4XYKnzPEbQGWKr9T5I0ht"; // bare base64 token (M: entropy path)
  it("does NOT capture a -----BEGIN PUBLIC KEY----- block (interior body lines excluded as a region)", () => {
    expect(findCandidates(publicKey)).toEqual([]);
  });
  it("does NOT capture a data:image/png;base64 payload (embedded asset)", () => {
    expect(findCandidates(dataUri)).toEqual([]);
  });
  it("STILL captures a -----BEGIN PRIVATE KEY----- block (existing PEM path, spans the region boundaries)", () => {
    const cs = findCandidates(privateKey);
    expect(cs.length).toBeGreaterThanOrEqual(1);
    expect(cs[0]!.hint).toBe("private_key");
    expect(cs[0]!.confidence).toBe("anchored");
  });
  it("captures a lone base64 blob OUTSIDE any PEM region (entropy path still works)", () => {
    const cs = findCandidates(`secret=${blob}`);
    expect(cs.length).toBe(1);
    expect(cs[0]!.value).toBe(blob);
  });
  it("captures a real secret next to a public key block (no cross-contamination)", () => {
    const text = `${publicKey}\nalso password=Tr0ub4dor3xyzabcQ`; // key= value is a separate KV secret
    const cs = findCandidates(text);
    // the PUBLIC key body is excluded; the KV password is still captured
    expect(cs.some((c) => c.value === "Tr0ub4dor3xyzabcQ")).toBe(true);
    expect(cs.every((c) => !c.value.startsWith("MFww"))).toBe(true);
  });
});

describe("task 17 — U: host-plus-path table for the URL gate", () => {
  it("drops api.slack.com docs/method links (no ingest path)", () => {
    expect(findCandidates("api_docs_url=https://api.slack.com/methods/chat.postMessage")).toEqual([]);
  });
  it("drops grafana.com dashboard links (bare host, no ingest path)", () => {
    expect(findCandidates("dashboard_url=https://grafana.com/grafana/dashboards/1234-node-exporter")).toEqual([]);
  });
  it("keeps hooks.slack.com/services/ webhooks", () => {
    const hook = "https://hooks.slack.com/services/T01234567/B01234567/EXAMPLE-NOT-A-REAL-WEBHOOK";
    const cs = findCandidates(`url=${hook}`);
    expect(cs).toHaveLength(1);
    expect(cs[0]!.value).toBe(hook);
  });
  it("keeps discord.com/api/webhooks/ but drops discord CDN attachments", () => {
    const webhook = "https://discord.com/api/webhooks/123/abc-DEF-ghi";
    expect(findCandidates(`url=${webhook}`)[0]?.value).toBe(webhook);
    const cdn = "https://cdn.discordapp.com/attachments/123/456/image.png";
    expect(findCandidates(`url=${cdn}`)).toEqual([]);
  });
  it("keeps presigned S3 via the query arm (X-Amz-Credential) even on a bare host", () => {
    const s3 = "https://s3.amazonaws.com/bucket/obj?X-Amz-Credential=AKIAEXAMPLE%2F20260914%2Fus-east-1%2Fs3%2Faws4_request";
    const cs = findCandidates(`url=${s3}`);
    expect(cs).toHaveLength(1);
    expect(cs[0]!.value).toBe(s3);
  });
  it("keeps grafana.net ingest paths (collect/otlp/loki push/instances)", () => {
    const url = "https://logs-prod-us-central1.grafana.net/loki/api/v1/push";
    const cs = findCandidates(`url=${url}`);
    expect(cs).toHaveLength(1);
    expect(cs[0]!.value).toBe(url);
  });
  it("keeps *.ingest.sentry.io with a numeric project path", () => {
    const url = "https://123456.ingest.sentry.io/789/abc";
    const cs = findCandidates(`url=${url}`);
    expect(cs).toHaveLength(1);
    expect(cs[0]!.value).toBe(url);
  });
});

describe("task 17 — V: correctness nits", () => {
  it("V(c): padding is re-attached per occurrence, not from a global indexOf", () => {
    const text = "first dXNlcjpwYXNzd29yZDEyMw then dXNlcjpwYXNzd29yZDEyMw== done";
    const cs = findCandidates(text);
    const values = cs.map((c) => c.value);
    expect(values).toContain("dXNlcjpwYXNzd29yZDEyMw"); // unpadded occurrence stays 22 chars
    expect(values).toContain("dXNlcjpwYXNzd29yZDEyMw=="); // padded occurrence becomes 24 chars
    // every captured value is either the 22-char raw or a clean 24-char decodable form
    expect(cs.every((c) => c.value.length === 22 || (c.value.length === 24 && c.value.endsWith("==")))).toBe(true);
  });
  it("V(a): applyCapture tiebreaks equal-start candidates by end, independent of input order", () => {
    const text = "ABCDEFGHIJ";
    const a: CapturedItem = { candidate: { value: "ABC", start: 0, end: 3, confidence: "kv", hint: "k" }, name: "a" };
    const b: CapturedItem = { candidate: { value: "ABCDEFGHIJ", start: 0, end: 10, confidence: "entropy" }, name: "b" };
    const fwd = applyCapture(text, [a, b]);
    const rev = applyCapture(text, [b, a]);
    expect(fwd.text).toBe(rev.text);
    expect(fwd.captured.map((p) => p.name).sort()).toEqual(rev.captured.map((p) => p.name).sort());
    // the widest (b) wins the shared start deterministically
    expect(fwd.captured[0]!.name).toBe("b");
  });
});

describe("task 17 — W: context-word match is word-boundary", () => {
  it("does NOT fire 'aws' inside 'laws' or 'dev' inside 'development'", () => {
    // a token in a sentence that merely contains the substring of a context word must not inherit it
    const c = findCandidates("Lk2#mP9qWw8$Xy5zB3nVc7Rf1Jh4")[0]!; // bare entropy token, no real context
    const lawsCtx = suggestNameForTest(c, "the new laws take effect tomorrow Lk2#mP9qWw8$Xy5zB3nVc7Rf1Jh4", []);
    const devCtx = suggestNameForTest(c, "our development branch uses Lk2#mP9qWw8$Xy5zB3nVc7Rf1Jh4", []);
    expect(lawsCtx).not.toContain("aws");
    expect(devCtx).not.toContain("dev");
    expect(lawsCtx).toBe("secret"); // no real context word present
    expect(devCtx).toBe("secret");
  });
  it("still fires a genuine standalone context word (staging)", () => {
    const c = findCandidates(`use this for the staging deploy: ${GH}`)[0]!;
    expect(suggestNameForTest(c, `use this for the staging deploy: ${GH}`, [])).toBe("gh_staging_deploy");
  });
});
