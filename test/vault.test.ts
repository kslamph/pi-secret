import { beforeEach, describe, expect, it } from "vitest";
import { inspect } from "node:util";
import {
  Vault,
  activeVault,
  dropSessionVault,
  setActiveScopeKey,
  vaultForSession,
  __vaultRegistryForTests,
} from "../src/vault.ts";
import {
  derivedForms,
  envVarName,
  fingerprint,
  isValidName,
  parseRef,
  refToken,
} from "../src/refs.ts";
import { findRefs } from "../src/substitute.ts";

const K = "4f9c1a7e2b8d0a3c5e7f1b3d9a2c4e6f8b0d2a4c";
const GH = "ghp_A1b2C3d4E5f6G7h8I9j0K1L2M3N4O5P6Q7R8";

describe("name and ref parsing", () => {
  it("accepts lowercase names with separators, rejects the rest", () => {
    expect(isValidName("gh_pat")).toBe(true);
    expect(isValidName("a")).toBe(true);
    expect(isValidName("GH_pat")).toBe(false);
    expect(isValidName("9bad")).toBe(false);
    expect(isValidName("has space")).toBe(false);
    expect(isValidName("x".repeat(65))).toBe(false);
  });

  it("parses only a whole-string ref", () => {
    expect(parseRef("{{sec:gh_pat}}")).toBe("gh_pat");
    expect(parseRef("{{sec:no}}pe")).toBeUndefined();
    expect(parseRef("plain")).toBeUndefined();
  });

  // isValidName, REF_RE and parseRef are three independent literals that must agree
  // on the 64-char cap. Pin each one, or widening any of them passes the suite.
  it("caps a name at 64 characters in all three expressions", () => {
    expect(isValidName("x".repeat(64))).toBe(true);
    expect(isValidName("x".repeat(65))).toBe(false);
    expect(parseRef(refToken("x".repeat(64)))).toBe("x".repeat(64));
    expect(parseRef(refToken("x".repeat(65)))).toBeUndefined();
    expect(findRefs(refToken("x".repeat(64))).map((r) => r.name)).toEqual(["x".repeat(64)]);
    expect(findRefs(refToken("x".repeat(65)))).toEqual([]);
  });
});

describe("fingerprint and derived forms", () => {
  it("fingerprint is 4 hex and depends only on the value", () => {
    expect(fingerprint("a")).toMatch(/^[0-9a-f]{4}$/);
    expect(fingerprint("abc")).toBe(fingerprint("abc"));
    expect(fingerprint("abc")).not.toBe(fingerprint("abd"));
  });

  it("derived forms are the value plus base64/base64url/hex", () => {
    const forms = derivedForms("abc");
    expect(forms[0]).toBe("abc");
    expect(forms).toContain(Buffer.from("abc").toString("base64"));
    expect(forms).toContain("616263");
  });
});

describe("Vault", () => {
  let v: Vault;
  beforeEach(() => {
    v = new Vault("s1");
  });

  it("stores a value with provenance and derived metadata", () => {
    const e = v.add("gh_pat", GH, "prompt");
    expect(e).toMatchObject({ name: "gh_pat", tier: "session", source: "prompt", length: GH.length });
    expect(e.fingerprint).toBe(fingerprint(GH));
    expect(v.get("gh_pat")?.value).toBe(GH);
    expect(v.resolve("gh_pat")).toBe(GH);
    expect(v.names()).toEqual(["gh_pat"]);
    expect(v.size()).toBe(1);
  });

  it("rejects bad names, empty values, and huge values", () => {
    expect(() => v.add("Bad Name", GH, "prompt")).toThrow(/invalid secret name/);
    expect(() => v.add("ok", "   ", "prompt")).toThrow(/empty/);
    expect(() => v.add("ok", "a".repeat(2 * 1024 * 1024), "prompt")).toThrow(/too large/);
    expect(v.names()).toEqual([]);
  });

  it("re-adding a name overwrites rather than duplicating", () => {
    v.add("k", K, "prompt");
    v.add("k", GH, "paste");
    expect(v.size()).toBe(1);
    expect(v.get("k")).toMatchObject({ source: "paste", value: GH });
  });

  it("finds an existing name for the same value", () => {
    v.add("a", GH, "prompt");
    expect(v.findByValue(GH)?.name).toBe("a");
    expect(v.findByValue("nope")).toBeUndefined();
  });

  it("renames and removes", () => {
    v.add("old", GH, "prompt");
    expect(v.rename("old", "new")).toBe(true);
    expect(v.rename("old", "newer")).toBe(false);
    expect(v.resolve("new")).toBe(GH);
    expect(v.remove("new")).toBe(true);
    expect(v.remove("new")).toBe(false);
    expect(v.size()).toBe(0);
  });

  it("never puts a value in the debug view", () => {
    v.add("gh_pat", GH, "prompt");
    const safe = v.entries()[0]!;
    expect(JSON.stringify(v)).not.toContain(GH);
    expect(safe).not.toHaveProperty("value");
  });

  it("gives punctuation-variant and long-prefix names distinct variables", () => {
    expect(envVarName("a-b")).not.toBe(envVarName("a_b"));
    const long = "x".repeat(45);
    // This pair shared a variable under a 40-char window plus a 32-bit tag.
    expect(envVarName(long + "4a5")).not.toBe(envVarName(long + "1y32"));
  });

  it("never yields the same variable across a 20k-name corpus", () => {
    const seen = new Map<string, string>();
    for (let i = 0; i < 20000; i++) {
      const name = ("c" + i.toString(36)).padEnd(2, "z").slice(0, 64);
      const varName = envVarName(name);
      expect(seen.has(varName), `collided with ${seen.get(varName)}`).toBe(false);
      seen.set(varName, name);
    }
  });

  it("refuses a name whose shell variable is already taken", () => {
    // A genuine 64-bit collision is not findable, and vi.mock("../src/refs.ts")
    // would not help: the guard's default resolver binds refs.ts's own export, so
    // a module mock changes the message, not the comparison. Inject the resolver.
    const flat = () => "__PISEC_FLAT_0000000000000000";
    const w = new Vault("t", flat);
    w.add("first", GH, "prompt");
    expect(() => w.add("second", K, "paste")).toThrow(/collides with/);
    expect(w.names()).toEqual(["first"]);
  });

  it("refuses a rename onto a colliding variable too", () => {
    // Flat-for-the-pair, not flat-for-everything: an always-flat resolver would
    // make the second add() throw during setup (every name collides with every
    // other), so only second/third share a variable and the rename targets it.
    const flat = (n: string) =>
      n === "second" || n === "third" ? "__PISEC_FLAT_0000000000000000" : `__PISEC_${n.toUpperCase()}`;
    const w = new Vault("t", flat);
    w.add("first", GH, "prompt");
    w.add("second", K, "paste");
    const real = new Vault("t");
    real.add("a-b", GH, "prompt");
    expect(() => w.rename("first", "third")).toThrow(/collides with/);
    expect(real.rename("a-b", "a_b")).toBe(true);
    expect(real.names()).toEqual(["a_b"]);
  });

  it("keeps a non-colliding rename on the non-throwing path", () => {
    // The pair above only pins the throw. rename() is PARTIALLY throwing: false for
    // unknown/invalid/taken names, a thrown Error only for an env-var collision —
    // so a guard that over-fired (rejecting an ordinary rename because the entry
    // collides with its OWN current name) would satisfy that test while making
    // /sec rename useless. Both mutations are covered, one test each: delete
    // rename()'s guard and only the pair above fails; drop the `ignore` argument
    // so the guard sees the entry's own name, and only this one fails.
    // (Verified by mutating the source, not by inspection.)
    const flat = (n: string) =>
      n === "second" || n === "third" ? "__PISEC_FLAT_0000000000000000" : `__PISEC_${n.toUpperCase()}`;
    const w = new Vault("t", flat);
    w.add("first", GH, "prompt");
    w.add("second", K, "paste");
    expect(() => w.rename("second", "third")).not.toThrow();
    expect(w.names()).toEqual(["first", "third"]);
  });

  it("hands out a frozen entry so its name cannot drift from its key", () => {
    v.add("gh_pat", GH, "prompt");
    const entry = v.get("gh_pat");
    expect(entry).toBeDefined();
    expect(() => {
      (entry as { name: string }).name = "renamed";
    }).toThrow();
    expect(v.get("gh_pat")?.name).toBe("gh_pat");
  });

  it("accepts punctuation-variant names that really do differ", () => {
    v.add("a-b", GH, "prompt");
    expect(() => v.add("a_b", K, "paste")).not.toThrow();
    expect(v.names()).toEqual(["a-b", "a_b"]);
  });

  it("hides values from util.inspect, not just JSON.stringify", () => {
    v.add("gh_pat", GH, "prompt");
    expect(inspect(v)).not.toContain(GH);
    expect(inspect(v, { customInspect: false })).not.toContain(GH);
  });

  it("returns a value-free projection from add()", () => {
    // A toMatchObject failure on a value-bearing entry prints the secret to CI.
    expect("value" in v.add("gh_pat", GH, "prompt")).toBe(false);
  });

  it("clear() wipes values and reports how many", () => {
    v.add("a", GH, "prompt");
    v.add("b", K, "paste");
    expect(v.clear()).toBe(2);
    expect(v.values()).toEqual([]);
  });
});

describe("session scoping", () => {
  beforeEach(() => {
    for (const key of [...__vaultRegistryForTests().keys()]) dropSessionVault(key);
    setActiveScopeKey(undefined);
  });

  it("keys vaults by session so reload reclaims the same one", () => {
    setActiveScopeKey("/tmp/a.jsonl");
    activeVault().add("k", GH, "prompt");
    setActiveScopeKey("/tmp/a.jsonl");
    expect(activeVault().resolve("k")).toBe(GH);
  });

  it("refuses to hand out a vault when no scope is bound", () => {
    setActiveScopeKey(undefined);
    expect(() => activeVault()).toThrow(/no session scope bound/);
    // The old "ephemeral" fallback was never dropped by any teardown path.
    expect(__vaultRegistryForTests().has("ephemeral")).toBe(false);
  });

  it("drops only the targeted session", () => {
    vaultForSession("/tmp/a.jsonl").add("k", GH, "prompt");
    vaultForSession("/tmp/b.jsonl").add("k", K, "prompt");
    dropSessionVault("/tmp/a.jsonl");
    expect(vaultForSession("/tmp/b.jsonl").resolve("k")).toBe(K);
    expect(vaultForSession("/tmp/a.jsonl").size()).toBe(0);
  });
});
